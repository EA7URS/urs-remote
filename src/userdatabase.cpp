#include "userdatabase.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>
#include <QSet>
#include <QVariant>
#include <cstring>

namespace {
constexpr int PasswordIterations = 600000;
constexpr int SessionLifetimeSeconds = 8 * 60 * 60;

QByteArray hmacSha256(const QByteArray &key, const QByteArray &message)
{
    constexpr int blockSize = 64;
    QByteArray actualKey = key;
    if (actualKey.size() > blockSize)
        actualKey = QCryptographicHash::hash(actualKey, QCryptographicHash::Sha256);
    if (actualKey.size() < blockSize)
        actualKey.append(QByteArray(blockSize - actualKey.size(), char(0)));

    QByteArray innerPad(blockSize, char(0x36));
    QByteArray outerPad(blockSize, char(0x5c));
    for (int i = 0; i < blockSize; ++i) {
        const uchar b = static_cast<uchar>(actualKey.at(i));
        innerPad[i] = char(static_cast<uchar>(innerPad.at(i)) ^ b);
        outerPad[i] = char(static_cast<uchar>(outerPad.at(i)) ^ b);
    }
    const QByteArray inner = QCryptographicHash::hash(innerPad + message,
                                                       QCryptographicHash::Sha256);
    return QCryptographicHash::hash(outerPad + inner, QCryptographicHash::Sha256);
}

QByteArray pbkdf2Sha256(const QByteArray &password, const QByteArray &salt, int iterations)
{
    QByteArray block = salt;
    block.append(char(0));
    block.append(char(0));
    block.append(char(0));
    block.append(char(1));

    QByteArray u = hmacSha256(password, block);
    QByteArray result = u;
    for (int i = 1; i < iterations; ++i) {
        u = hmacSha256(password, u);
        for (int j = 0; j < result.size(); ++j)
            result[j] = char(static_cast<uchar>(result.at(j)) ^ static_cast<uchar>(u.at(j)));
    }
    return result;
}

QByteArray randomBytes(int count)
{
    QByteArray bytes(count, char(0));
    for (int i = 0; i < count; i += int(sizeof(quint32))) {
        const quint32 value = QRandomGenerator::system()->generate();
        const int copySize = qMin(int(sizeof(value)), count - i);
        std::memcpy(bytes.data() + i, &value, size_t(copySize));
    }
    return bytes;
}

bool constantTimeEqual(const QByteArray &left, const QByteArray &right)
{
    if (left.size() != right.size()) return false;
    uchar difference = 0;
    for (int i = 0; i < left.size(); ++i)
        difference |= static_cast<uchar>(left.at(i)) ^ static_cast<uchar>(right.at(i));
    return difference == 0;
}

QString queryError(const QSqlQuery &query)
{
    return query.lastError().text();
}

bool validProfile(const QJsonObject &profile, bool includeEmail, QString *error)
{
    static const QRegularExpression validEmail(QStringLiteral("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$"));
    const QString userId = UserDatabase::normalizedUserId(profile.value(QStringLiteral("userId")).toString());
    static const QRegularExpression validId(QStringLiteral("^[A-Z0-9][A-Z0-9._-]{0,31}$"));
    if (!validId.match(userId).hasMatch()) {
        if (error) *error = QStringLiteral("El indicativo debe tener entre 1 y 32 letras, números, puntos, guiones o guiones bajos.");
        return false;
    }
    const QStringList required = {QStringLiteral("firstName"), QStringLiteral("lastName")};
    for (const QString &field : required) {
        const QString value = profile.value(field).toString().trimmed();
        if (value.isEmpty() || value.size() > 120) {
            if (error) *error = QStringLiteral("Completa los campos obligatorios del perfil (máximo 120 caracteres por campo).");
            return false;
        }
    }
    const QStringList optionalAddress = {QStringLiteral("street"), QStringLiteral("city"),
                                         QStringLiteral("postalCode"), QStringLiteral("province")};
    for (const QString &field : optionalAddress) {
        if (profile.value(field).toString().trimmed().size() > 120) {
            if (error) *error = QStringLiteral("Los datos de dirección no pueden superar 120 caracteres por campo.");
            return false;
        }
    }
    if (includeEmail) {
        const QString email = profile.value(QStringLiteral("email")).toString().trimmed();
        if (email.size() > 254 || !validEmail.match(email).hasMatch()) {
            if (error) *error = QStringLiteral("Introduce una dirección de correo válida.");
            return false;
        }
    }
    const QString role = profile.value(QStringLiteral("operationalProfile")).toString();
    if (!role.isEmpty() && role != QLatin1String("licensed") && role != QLatin1String("capture")) {
        if (error) *error = QStringLiteral("El perfil operativo no es válido.");
        return false;
    }
    return true;
}
}

UserDatabase::~UserDatabase()
{
    if (db_.isValid()) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connectionName_);
    }
}

QString UserDatabase::normalizedUserId(const QString &userId)
{
    return userId.trimmed().toUpper();
}

bool UserDatabase::validPassword(const QString &password)
{
    return password.size() >= 12 && password.toUtf8().size() <= 256;
}

bool UserDatabase::open(const QString &path, QString *error)
{
    connectionName_ = QStringLiteral("wfweb-users-%1")
            .arg(reinterpret_cast<quintptr>(this), 0, 16);
    db_ = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName_);
    db_.setDatabaseName(path);
    if (!db_.open()) {
        if (error) *error = db_.lastError().text();
        return false;
    }

    QSqlQuery pragma(db_);
    pragma.exec(QStringLiteral("PRAGMA foreign_keys = ON"));
    pragma.exec(QStringLiteral("PRAGMA journal_mode = WAL"));
    pragma.exec(QStringLiteral("PRAGMA busy_timeout = 5000"));
    pragma.finish();

    if (!createSchema(error) || !seedInitialAdmin(error)) return false;
    QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner);
    QFile::setPermissions(path + QStringLiteral("-wal"), QFile::ReadOwner | QFile::WriteOwner);
    QFile::setPermissions(path + QStringLiteral("-shm"), QFile::ReadOwner | QFile::WriteOwner);
    return true;
}

bool UserDatabase::createSchema(QString *error)
{
    QSqlQuery query(db_);
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS users ("
            "user_id TEXT PRIMARY KEY COLLATE NOCASE, "
            "password_hash TEXT NOT NULL, "
            "is_admin INTEGER NOT NULL DEFAULT 0, "
            "must_change_password INTEGER NOT NULL DEFAULT 0, "
            "operational_profile TEXT NOT NULL DEFAULT 'licensed', "
            "first_name TEXT NOT NULL DEFAULT '', "
            "last_name TEXT NOT NULL DEFAULT '', "
            "email TEXT NOT NULL DEFAULT '', "
            "street TEXT NOT NULL DEFAULT '', "
            "city TEXT NOT NULL DEFAULT '', "
            "postal_code TEXT NOT NULL DEFAULT '', "
            "province TEXT NOT NULL DEFAULT '', "
            "created_at INTEGER NOT NULL)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "token_hash BLOB PRIMARY KEY, "
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, "
            "expires_at INTEGER NOT NULL)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id)"));
    return migrateSchema(error);
}

bool UserDatabase::migrateSchema(QString *error)
{
    QSet<QString> columns;
    QSqlQuery info(db_);
    if (!info.exec(QStringLiteral("PRAGMA table_info(users)"))) {
        if (error) *error = queryError(info);
        return false;
    }
    while (info.next()) columns.insert(info.value(1).toString());
    info.finish();

    const QList<QPair<QString, QString>> additions = {
        {QStringLiteral("operational_profile"), QStringLiteral("TEXT NOT NULL DEFAULT 'licensed'")},
        {QStringLiteral("first_name"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("last_name"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("email"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("street"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("city"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("postal_code"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("province"), QStringLiteral("TEXT NOT NULL DEFAULT ''")}
    };
    for (const auto &column : additions) {
        if (columns.contains(column.first)) continue;
        QSqlQuery alter(db_);
        if (!alter.exec(QStringLiteral("ALTER TABLE users ADD COLUMN %1 %2")
                        .arg(column.first, column.second))) {
            if (error) *error = queryError(alter);
            return false;
        }
    }

    QSqlQuery tableSql(db_);
    tableSql.exec(QStringLiteral("SELECT sql FROM sqlite_master WHERE type='table' AND name='sessions'"));
    const QString currentSql = tableSql.next() ? tableSql.value(0).toString() : QString();
    tableSql.finish();
    if (currentSql.contains(QStringLiteral("ON UPDATE CASCADE"), Qt::CaseInsensitive))
        return true;

    // User IDs are editable callsigns. Rebuild sessions once with a cascading
    // foreign key so those changes preserve valid session tokens.
    QSqlQuery foreignKeysOff(db_);
    if (!foreignKeysOff.exec(QStringLiteral("PRAGMA foreign_keys = OFF"))) {
        if (error) *error = queryError(foreignKeysOff);
        return false;
    }
    foreignKeysOff.finish();
    if (!db_.transaction()) {
        if (error) *error = db_.lastError().text();
        QSqlQuery on(db_); on.exec(QStringLiteral("PRAGMA foreign_keys = ON"));
        return false;
    }
    const QStringList migration = {
        QStringLiteral("ALTER TABLE sessions RENAME TO sessions_before_profile_migration"),
        QStringLiteral("CREATE TABLE sessions (token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, expires_at INTEGER NOT NULL)"),
        QStringLiteral("INSERT INTO sessions(token_hash, user_id, expires_at) SELECT token_hash, user_id, expires_at FROM sessions_before_profile_migration"),
        QStringLiteral("DROP TABLE sessions_before_profile_migration"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id)")
    };
    for (const QString &statement : migration) {
        QSqlQuery step(db_);
        if (!step.exec(statement)) {
            if (error) *error = queryError(step);
            db_.rollback();
            QSqlQuery on(db_); on.exec(QStringLiteral("PRAGMA foreign_keys = ON"));
            return false;
        }
    }
    if (!db_.commit()) {
        if (error) *error = db_.lastError().text();
        db_.rollback();
        QSqlQuery on(db_); on.exec(QStringLiteral("PRAGMA foreign_keys = ON"));
        return false;
    }
    QSqlQuery foreignKeysOn(db_);
    if (!foreignKeysOn.exec(QStringLiteral("PRAGMA foreign_keys = ON"))) {
        if (error) *error = queryError(foreignKeysOn);
        return false;
    }
    return true;
}

bool UserDatabase::seedInitialAdmin(QString *error)
{
    QSqlQuery count(db_);
    if (!count.exec(QStringLiteral("SELECT COUNT(*) FROM users")) || !count.next()) {
        if (error) *error = queryError(count);
        return false;
    }
    if (count.value(0).toInt() != 0) return true;
    count.finish();

    QSqlQuery insert(db_);
    insert.prepare(QStringLiteral(
        "INSERT INTO users(user_id, password_hash, is_admin, must_change_password, created_at) "
        "VALUES(?, ?, 1, 1, ?)"));
    insert.addBindValue(QStringLiteral("EA7URS"));
    insert.addBindValue(passwordHash(QStringLiteral("EA7URS")));
    insert.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!insert.exec()) {
        if (error) *error = queryError(insert);
        return false;
    }
    return true;
}

QString UserDatabase::passwordHash(const QString &password)
{
    const QByteArray salt = randomBytes(16);
    const QByteArray hash = pbkdf2Sha256(password.toUtf8(), salt, PasswordIterations);
    return QStringLiteral("pbkdf2-sha256$%1$%2$%3")
            .arg(PasswordIterations)
            .arg(QString::fromLatin1(salt.toBase64(QByteArray::Base64UrlEncoding |
                                                   QByteArray::OmitTrailingEquals)))
            .arg(QString::fromLatin1(hash.toBase64(QByteArray::Base64UrlEncoding |
                                                  QByteArray::OmitTrailingEquals)));
}

bool UserDatabase::passwordMatches(const QString &password, const QString &storedHash)
{
    const QStringList parts = storedHash.split(QLatin1Char('$'));
    if (parts.size() != 4 || parts.at(0) != QLatin1String("pbkdf2-sha256")) return false;
    bool ok = false;
    const int iterations = parts.at(1).toInt(&ok);
    if (!ok || iterations < 100000 || iterations > 2000000) return false;
    const QByteArray salt = QByteArray::fromBase64(parts.at(2).toLatin1(), QByteArray::Base64UrlEncoding);
    const QByteArray expected = QByteArray::fromBase64(parts.at(3).toLatin1(), QByteArray::Base64UrlEncoding);
    if (salt.size() != 16 || expected.size() != 32) return false;
    return constantTimeEqual(pbkdf2Sha256(password.toUtf8(), salt, iterations), expected);
}

bool UserDatabase::verifyCredentials(const QString &userId, const QString &password,
                                     AuthUser *user) const
{
    const QString id = normalizedUserId(userId);
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT user_id, password_hash, is_admin, must_change_password, operational_profile "
                                 "FROM users WHERE user_id = ?"));
    query.addBindValue(id);
    if (!query.exec()) return false;
    if (!query.next()) {
        // Keep unknown-user failures close to the cost of a real password check.
        static const QString dummy = QStringLiteral(
            "pbkdf2-sha256$600000$d2ZiZXctYXV0aC1kdW1teQ$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        passwordMatches(password, dummy);
        return false;
    }
    if (!passwordMatches(password, query.value(1).toString())) return false;
    if (user) {
        user->userId = query.value(0).toString();
        user->isAdmin = query.value(2).toInt() != 0;
        user->mustChangePassword = query.value(3).toInt() != 0;
        user->operationalProfile = query.value(4).toString();
        user->authenticated = true;
    }
    return true;
}

QByteArray UserDatabase::tokenHash(const QString &token)
{
    return QCryptographicHash::hash(token.toLatin1(), QCryptographicHash::Sha256);
}

bool UserDatabase::createSession(const QString &userId, QString *token, qint64 *expiresAt)
{
    const QString id = normalizedUserId(userId);
    const QString rawToken = QString::fromLatin1(randomBytes(32).toHex());
    const qint64 expiry = QDateTime::currentSecsSinceEpoch() + SessionLifetimeSeconds;
    QSqlQuery cleanup(db_);
    cleanup.prepare(QStringLiteral("DELETE FROM sessions WHERE expires_at <= ?"));
    cleanup.addBindValue(QDateTime::currentSecsSinceEpoch());
    cleanup.exec();

    QSqlQuery insert(db_);
    insert.prepare(QStringLiteral("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES(?, ?, ?)"));
    insert.addBindValue(tokenHash(rawToken));
    insert.addBindValue(id);
    insert.addBindValue(expiry);
    if (!insert.exec()) return false;
    if (token) *token = rawToken;
    if (expiresAt) *expiresAt = expiry;
    return true;
}

AuthUser UserDatabase::userForSession(const QString &token) const
{
    AuthUser user;
    if (token.isEmpty()) return user;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral(
        "SELECT u.user_id, u.is_admin, u.must_change_password, s.expires_at, u.operational_profile "
        "FROM sessions s JOIN users u ON u.user_id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?"));
    query.addBindValue(tokenHash(token));
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec() || !query.next()) return user;
    user.userId = query.value(0).toString();
    user.isAdmin = query.value(1).toInt() != 0;
    user.mustChangePassword = query.value(2).toInt() != 0;
    user.sessionExpiresAt = query.value(3).toLongLong();
    user.operationalProfile = query.value(4).toString();
    user.authenticated = true;
    return user;
}

bool UserDatabase::changePassword(const QString &userId, const QString &password, QString *error)
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("UPDATE users SET password_hash = ?, must_change_password = 0 "
                                 "WHERE user_id = ?"));
    query.addBindValue(passwordHash(password));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec() || query.numRowsAffected() != 1) {
        if (error) *error = query.lastError().text();
        return false;
    }
    return true;
}

bool UserDatabase::createUser(const QJsonObject &profileData, const QString &password,
                              bool makeAdmin, QString *error)
{
    if (!validProfile(profileData, true, error)) return false;
    const QString id = normalizedUserId(profileData.value(QStringLiteral("userId")).toString());
    if (!validPassword(password)) {
        if (error) *error = QStringLiteral("Password must be at least 12 characters and no more than 256 UTF-8 bytes.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral(
        "INSERT INTO users(user_id, password_hash, is_admin, must_change_password, operational_profile, "
        "first_name, last_name, email, street, city, postal_code, province, created_at) "
        "VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    query.addBindValue(id);
    query.addBindValue(passwordHash(password));
    query.addBindValue(makeAdmin ? 1 : 0);
    const QString role = profileData.value(QStringLiteral("operationalProfile")).toString();
    query.addBindValue(role.isEmpty() ? QStringLiteral("licensed") : role);
    query.addBindValue(profileData.value(QStringLiteral("firstName")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("lastName")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("email")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("street")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("city")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("postalCode")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("province")).toString().trimmed());
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec()) {
        if (error) *error = query.lastError().text().contains(QStringLiteral("UNIQUE"), Qt::CaseInsensitive)
                ? QStringLiteral("That user ID already exists.") : query.lastError().text();
        return false;
    }
    return true;
}

bool UserDatabase::promoteUser(const QString &userId, QString *error)
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("UPDATE users SET is_admin = 1 WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec() || query.numRowsAffected() == 0) {
        if (error) *error = query.lastError().text().isEmpty()
                ? QStringLiteral("User not found.") : query.lastError().text();
        return false;
    }
    return true;
}

QJsonArray UserDatabase::users() const
{
    QJsonArray result;
    QSqlQuery query(db_);
    if (!query.exec(QStringLiteral("SELECT user_id, is_admin, must_change_password, operational_profile, "
                                   "first_name, last_name, email, street, city, postal_code, province "
                                   "FROM users ORDER BY user_id COLLATE NOCASE")))
        return result;
    while (query.next()) {
        result.append(QJsonObject{{"userId", query.value(0).toString()},
                                  {"isAdmin", query.value(1).toInt() != 0},
                                  {"mustChangePassword", query.value(2).toInt() != 0},
                                  {"operationalProfile", query.value(3).toString()},
                                  {"firstName", query.value(4).toString()},
                                  {"lastName", query.value(5).toString()},
                                  {"email", query.value(6).toString()},
                                  {"street", query.value(7).toString()},
                                  {"city", query.value(8).toString()},
                                  {"postalCode", query.value(9).toString()},
                                  {"province", query.value(10).toString()}});
    }
    return result;
}

QJsonObject UserDatabase::profile(const QString &userId) const
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT user_id, operational_profile, first_name, last_name, email, "
                                 "street, city, postal_code, province FROM users WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec() || !query.next()) return QJsonObject();
    return QJsonObject{{"userId", query.value(0).toString()},
                       {"operationalProfile", query.value(1).toString()},
                       {"firstName", query.value(2).toString()},
                       {"lastName", query.value(3).toString()},
                       {"email", query.value(4).toString()},
                       {"street", query.value(5).toString()},
                       {"city", query.value(6).toString()},
                       {"postalCode", query.value(7).toString()},
                       {"province", query.value(8).toString()}};
}

bool UserDatabase::updateOwnProfile(const QString &userId, const QJsonObject &profileData,
                                    QString *newUserId, QString *error)
{
    return updateProfile(userId, profileData, false, newUserId, error);
}

bool UserDatabase::updateAdminUser(const QString &userId, const QJsonObject &profileData,
                                   QString *newUserId, QString *error)
{
    return updateProfile(userId, profileData, true, newUserId, error);
}

bool UserDatabase::updateProfile(const QString &userId, const QJsonObject &profileData,
                                 bool administrator, QString *newUserId, QString *error)
{
    if (!validProfile(profileData, administrator, error)) return false;
    const QString oldId = normalizedUserId(userId);
    const QString newId = normalizedUserId(profileData.value(QStringLiteral("userId")).toString());
    const QString role = profileData.value(QStringLiteral("operationalProfile")).toString();
    if (administrator && role.isEmpty()) {
        if (error) *error = QStringLiteral("Selecciona un perfil operativo.");
        return false;
    }
    if (!db_.transaction()) {
        if (error) *error = db_.lastError().text();
        return false;
    }
    QSqlQuery update(db_);
    QString sql = QStringLiteral("UPDATE users SET user_id = ?, first_name = ?, last_name = ?, "
                                 "street = ?, city = ?, postal_code = ?, province = ?");
    if (administrator)
        sql += QStringLiteral(", email = ?, operational_profile = ?");
    sql += QStringLiteral(" WHERE user_id = ?");
    update.prepare(sql);
    update.addBindValue(newId);
    update.addBindValue(profileData.value(QStringLiteral("firstName")).toString().trimmed());
    update.addBindValue(profileData.value(QStringLiteral("lastName")).toString().trimmed());
    update.addBindValue(profileData.value(QStringLiteral("street")).toString().trimmed());
    update.addBindValue(profileData.value(QStringLiteral("city")).toString().trimmed());
    update.addBindValue(profileData.value(QStringLiteral("postalCode")).toString().trimmed());
    update.addBindValue(profileData.value(QStringLiteral("province")).toString().trimmed());
    if (administrator) {
        update.addBindValue(profileData.value(QStringLiteral("email")).toString().trimmed());
        update.addBindValue(role);
    }
    update.addBindValue(oldId);
    if (!update.exec() || update.numRowsAffected() != 1) {
        const QString dbError = queryError(update);
        if (error) *error = dbError.contains(QStringLiteral("UNIQUE"), Qt::CaseInsensitive)
                ? QStringLiteral("Ese indicativo ya está asignado a otra cuenta.")
                : (dbError.isEmpty() ? QStringLiteral("No se encontró la cuenta.") : dbError);
        db_.rollback();
        return false;
    }
    if (!db_.commit()) {
        if (error) *error = db_.lastError().text();
        db_.rollback();
        return false;
    }
    if (newUserId) *newUserId = newId;
    return true;
}

bool UserDatabase::canTransmit(const QString &userId) const
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT operational_profile FROM users WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    return query.exec() && query.next() && query.value(0).toString() == QLatin1String("licensed");
}

void UserDatabase::revokeSessions(const QString &userId)
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("DELETE FROM sessions WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    query.exec();
}

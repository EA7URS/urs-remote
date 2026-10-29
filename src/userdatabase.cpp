#include "userdatabase.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDate>
#include <QFile>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>
#include <QSet>
#include <QTime>
#include <QUuid>
#include <QVariant>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace {
constexpr int PasswordIterations = 600000;
constexpr int SessionLifetimeSeconds = 8 * 60 * 60;
constexpr qint64 MaximumReservationMinutes = 2147483647LL;

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

bool validatedUsageLimit(const QJsonObject &profile, const QString &field,
                         qint64 maximumMinutes, qint64 *minutes, QString *error)
{
    const QJsonValue value = profile.value(field);
    if (value.isUndefined() || value.isNull()
            || (value.isString() && value.toString().trimmed().isEmpty())) {
        if (minutes) *minutes = -1;
        return true;
    }
    if (!value.isDouble()) {
        if (error) *error = QStringLiteral("Los límites deben ser cantidades de minutos o quedar vacíos.");
        return false;
    }
    const double number = value.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number || number < 1
            || number > maximumMinutes) {
        if (error) *error = QStringLiteral("Uno de los límites de tiempo no está dentro del intervalo permitido.");
        return false;
    }
    if (minutes) *minutes = static_cast<qint64>(number);
    return true;
}

bool validatedReservationTime(const QJsonValue &value, qint64 *minutes, QString *error)
{
    if (value.isUndefined() || value.isNull()
            || (value.isString() && value.toString().trimmed().isEmpty())) {
        if (minutes) *minutes = 0;
        return true;
    }
    bool ok = false;
    const double number = value.isString() ? value.toString().trimmed().toDouble(&ok)
                                           : (value.isDouble() ? value.toDouble() : 0.0);
    if (value.isDouble()) ok = true;
    if (!ok || !std::isfinite(number) || std::floor(number) != number || number < 0
            || number > MaximumReservationMinutes) {
        if (error) *error = QStringLiteral("El tiempo máximo por reserva debe ser un entero no negativo de minutos.");
        return false;
    }
    if (minutes) *minutes = static_cast<qint64>(number);
    return true;
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
            "CREATE TABLE IF NOT EXISTS usage_profiles ("
            "profile_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL COLLATE NOCASE UNIQUE, "
            "daily_limit_minutes INTEGER, "
            "weekly_limit_minutes INTEGER, "
            "monthly_limit_minutes INTEGER, "
            "created_at INTEGER NOT NULL, "
            "updated_at INTEGER NOT NULL)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS users ("
            "user_id TEXT PRIMARY KEY COLLATE NOCASE, "
            "password_hash TEXT NOT NULL, "
            "is_admin INTEGER NOT NULL DEFAULT 0, "
            "must_change_password INTEGER NOT NULL DEFAULT 0, "
            "operational_profile TEXT NOT NULL DEFAULT 'licensed', "
            "usage_profile_id INTEGER REFERENCES usage_profiles(profile_id) ON DELETE SET NULL, "
            "first_name TEXT NOT NULL DEFAULT '', "
            "last_name TEXT NOT NULL DEFAULT '', "
            "email TEXT NOT NULL DEFAULT '', "
            "street TEXT NOT NULL DEFAULT '', "
            "city TEXT NOT NULL DEFAULT '', "
            "postal_code TEXT NOT NULL DEFAULT '', "
            "province TEXT NOT NULL DEFAULT '', "
            "max_reservation_minutes INTEGER NOT NULL DEFAULT 0, "
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
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS radio_usage_sessions ("
            "session_id TEXT PRIMARY KEY, "
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, "
            "started_at INTEGER NOT NULL, "
            "ended_at INTEGER)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS radio_usage_resets ("
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, "
            "period TEXT NOT NULL CHECK(period IN ('daily', 'weekly', 'monthly')), "
            "reset_at INTEGER NOT NULL, "
            "PRIMARY KEY(user_id, period))"))) {
        if (error) *error = queryError(query);
        return false;
    }
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS radio_reservations ("
            "reservation_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE, "
            "starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL, "
            "status TEXT NOT NULL DEFAULT 'confirmed' CHECK(status IN ('confirmed', 'cancelled')), "
            "created_at INTEGER NOT NULL, CHECK(ends_at > starts_at))"))) {
        if (error) *error = queryError(query);
        return false;
    }
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id)"));
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS radio_usage_user_start ON radio_usage_sessions(user_id, started_at)"));
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS radio_reservations_start ON radio_reservations(status, starts_at, ends_at)"));
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS radio_reservations_user_start ON radio_reservations(user_id, status, starts_at)"));
    if (!migrateSchema(error)) return false;
    if (!query.exec(QStringLiteral("UPDATE radio_usage_sessions SET ended_at = started_at WHERE ended_at IS NULL"))) {
        if (error) *error = queryError(query);
        return false;
    }
    return true;
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
        {QStringLiteral("usage_profile_id"), QStringLiteral("INTEGER REFERENCES usage_profiles(profile_id) ON DELETE SET NULL")},
        {QStringLiteral("first_name"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("last_name"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("email"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("street"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("city"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("postal_code"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("province"), QStringLiteral("TEXT NOT NULL DEFAULT ''")},
        {QStringLiteral("max_reservation_minutes"), QStringLiteral("INTEGER NOT NULL DEFAULT 0")}
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
    query.prepare(QStringLiteral("SELECT user_id, password_hash, is_admin, must_change_password, operational_profile, "
                                 "usage_profile_id, COALESCE((SELECT name FROM usage_profiles "
                                 "WHERE profile_id = users.usage_profile_id), ''), max_reservation_minutes "
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
        user->usageProfileId = query.value(5).toLongLong();
        user->usageProfileName = query.value(6).toString();
        user->maxReservationMinutes = query.value(7).toLongLong();
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
        "SELECT u.user_id, u.is_admin, u.must_change_password, s.expires_at, u.operational_profile, "
        "u.usage_profile_id, COALESCE(p.name, ''), u.max_reservation_minutes "
        "FROM sessions s JOIN users u ON u.user_id = s.user_id "
        "LEFT JOIN usage_profiles p ON p.profile_id = u.usage_profile_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?"));
    query.addBindValue(tokenHash(token));
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec() || !query.next()) return user;
    user.userId = query.value(0).toString();
    user.isAdmin = query.value(1).toInt() != 0;
    user.mustChangePassword = query.value(2).toInt() != 0;
    user.sessionExpiresAt = query.value(3).toLongLong();
    user.operationalProfile = query.value(4).toString();
    user.usageProfileId = query.value(5).toLongLong();
    user.usageProfileName = query.value(6).toString();
    user.maxReservationMinutes = query.value(7).toLongLong();
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
    qint64 maxReservationMinutes = 0;
    if (!validatedReservationTime(profileData.value(QStringLiteral("maxReservationMinutes")),
                                  &maxReservationMinutes, error)) return false;
    qint64 usageProfileId = 0;
    if (!validateUsageAssignment(profileData.value(QStringLiteral("usageProfileId")),
                                 &usageProfileId, error)) return false;
    const QString id = normalizedUserId(profileData.value(QStringLiteral("userId")).toString());
    if (!validPassword(password)) {
        if (error) *error = QStringLiteral("Password must be at least 12 characters and no more than 256 UTF-8 bytes.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral(
        "INSERT INTO users(user_id, password_hash, is_admin, must_change_password, operational_profile, usage_profile_id, "
        "first_name, last_name, email, street, city, postal_code, province, max_reservation_minutes, created_at) "
        "VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
    query.addBindValue(id);
    query.addBindValue(passwordHash(password));
    query.addBindValue(makeAdmin ? 1 : 0);
    const QString role = profileData.value(QStringLiteral("operationalProfile")).toString();
    query.addBindValue(role.isEmpty() ? QStringLiteral("licensed") : role);
    query.addBindValue(usageProfileId > 0 ? QVariant(usageProfileId) : QVariant());
    query.addBindValue(profileData.value(QStringLiteral("firstName")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("lastName")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("email")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("street")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("city")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("postalCode")).toString().trimmed());
    query.addBindValue(profileData.value(QStringLiteral("province")).toString().trimmed());
    query.addBindValue(maxReservationMinutes);
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
    if (!query.exec(QStringLiteral("SELECT u.user_id, u.is_admin, u.must_change_password, u.operational_profile, "
                                   "u.first_name, u.last_name, u.email, u.street, u.city, u.postal_code, u.province, "
                                   "u.usage_profile_id, COALESCE(p.name, ''), u.max_reservation_minutes "
                                   "FROM users u LEFT JOIN usage_profiles p ON p.profile_id = u.usage_profile_id "
                                   "ORDER BY u.user_id COLLATE NOCASE")))
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
        QJsonObject user = result.last().toObject();
        user.insert(QStringLiteral("usageProfileId"), query.value(11).isNull()
                    ? QJsonValue(QJsonValue::Null) : QJsonValue(query.value(11).toLongLong()));
        user.insert(QStringLiteral("usageProfileName"), query.value(12).toString());
        user.insert(QStringLiteral("maxReservationMinutes"), query.value(13).toLongLong());
        result.replace(result.size() - 1, user);
    }
    query.finish();
    for (int i = 0; i < result.size(); ++i) {
        QJsonObject user = result.at(i).toObject();
        const QJsonObject reservation = reservationStatus(user.value(QStringLiteral("userId")).toString());
        user.insert(QStringLiteral("effectiveReservationMinutes"),
                    reservation.value(QStringLiteral("effectiveReservationMinutes")));
        user.insert(QStringLiteral("canReserve"), reservation.value(QStringLiteral("canReserve")));
        result.replace(i, user);
    }
    return result;
}

QJsonObject UserDatabase::profile(const QString &userId) const
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT u.user_id, u.operational_profile, u.first_name, u.last_name, u.email, "
                                 "u.street, u.city, u.postal_code, u.province, u.usage_profile_id, COALESCE(p.name, ''), "
                                 "u.max_reservation_minutes "
                                 "FROM users u LEFT JOIN usage_profiles p ON p.profile_id = u.usage_profile_id "
                                 "WHERE u.user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec() || !query.next()) return QJsonObject();
    const QString id = query.value(0).toString();
    const qint64 maxReservationMinutes = query.value(11).toLongLong();
    QJsonObject result{{"userId", id},
                       {"operationalProfile", query.value(1).toString()},
                       {"firstName", query.value(2).toString()},
                       {"lastName", query.value(3).toString()},
                       {"email", query.value(4).toString()},
                       {"street", query.value(5).toString()},
                       {"city", query.value(6).toString()},
                       {"postalCode", query.value(7).toString()},
                       {"province", query.value(8).toString()},
                       {"usageProfileId", query.value(9).isNull() ? QJsonValue(QJsonValue::Null)
                                                                    : QJsonValue(query.value(9).toLongLong())},
                       {"usageProfileName", query.value(10).toString()},
                       {"maxReservationMinutes", maxReservationMinutes}};
    query.finish();
    const QJsonObject reservation = reservationStatus(id);
    result.insert(QStringLiteral("effectiveReservationMinutes"),
                  reservation.value(QStringLiteral("effectiveReservationMinutes")));
    result.insert(QStringLiteral("canReserve"), reservation.value(QStringLiteral("canReserve")));
    return result;
}

QJsonObject UserDatabase::reservationStatus(const QString &userId) const
{
    const QString id = normalizedUserId(userId);
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT max_reservation_minutes FROM users WHERE user_id = ?"));
    query.addBindValue(id);
    if (!query.exec() || !query.next()) return QJsonObject();
    const qint64 maximumMinutes = query.value(0).toLongLong();
    query.finish();

    qint64 remainingSeconds = maximumMinutes * 60;
    const QJsonObject usage = usageStatus(id);
    if (!usage.value(QStringLiteral("found")).toBool()
            || !usage.value(QStringLiteral("allowed")).toBool()) {
        remainingSeconds = 0;
    } else {
        const QStringList periods = {QStringLiteral("daily"), QStringLiteral("weekly"),
                                     QStringLiteral("monthly")};
        for (const QString &period : periods) {
            const QJsonObject limit = usage.value(period).toObject();
            if (limit.isEmpty() || limit.value(QStringLiteral("limitMinutes")).isNull()
                    || limit.value(QStringLiteral("remainingSeconds")).isNull()) continue;
            remainingSeconds = qMin(remainingSeconds,
                                    limit.value(QStringLiteral("remainingSeconds")).toVariant().toLongLong());
        }
    }
    const qint64 effectiveMinutes = qMax<qint64>(0, remainingSeconds) / 60;
    return QJsonObject{{"maxReservationMinutes", maximumMinutes},
                       {"effectiveReservationMinutes", effectiveMinutes},
                       {"canReserve", effectiveMinutes > 0}};
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
    qint64 usageProfileId = 0;
    const bool updateUsageProfile = administrator && profileData.contains(QStringLiteral("usageProfileId"));
    if (updateUsageProfile && !validateUsageAssignment(profileData.value(QStringLiteral("usageProfileId")),
                                                       &usageProfileId, error)) return false;
    qint64 maxReservationMinutes = 0;
    const bool updateReservationTime = administrator
            && profileData.contains(QStringLiteral("maxReservationMinutes"));
    if (updateReservationTime
            && !validatedReservationTime(profileData.value(QStringLiteral("maxReservationMinutes")),
                                         &maxReservationMinutes, error)) return false;
    if (!db_.transaction()) {
        if (error) *error = db_.lastError().text();
        return false;
    }
    QSqlQuery update(db_);
    QString sql = QStringLiteral("UPDATE users SET user_id = ?, first_name = ?, last_name = ?, "
                                 "street = ?, city = ?, postal_code = ?, province = ?");
    if (administrator)
        sql += QStringLiteral(", email = ?, operational_profile = ?");
    if (updateUsageProfile)
        sql += QStringLiteral(", usage_profile_id = ?");
    if (updateReservationTime)
        sql += QStringLiteral(", max_reservation_minutes = ?");
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
    if (updateUsageProfile)
        update.addBindValue(usageProfileId > 0 ? QVariant(usageProfileId) : QVariant());
    if (updateReservationTime)
        update.addBindValue(maxReservationMinutes);
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

bool UserDatabase::validateUsageAssignment(const QJsonValue &profileId, qint64 *id,
                                           QString *error) const
{
    if (profileId.isUndefined() || profileId.isNull()
            || (profileId.isString() && profileId.toString().trimmed().isEmpty())) {
        if (id) *id = 0;
        return true;
    }
    bool ok = false;
    const qint64 value = profileId.isString() ? profileId.toString().toLongLong(&ok)
                                               : profileId.toVariant().toLongLong(&ok);
    if (!ok || value <= 0) {
        if (error) *error = QStringLiteral("Selecciona un perfil de tiempos válido.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT 1 FROM usage_profiles WHERE profile_id = ?"));
    query.addBindValue(value);
    if (!query.exec() || !query.next()) {
        if (error) *error = QStringLiteral("El perfil de tiempos seleccionado no existe.");
        return false;
    }
    if (id) *id = value;
    return true;
}

QJsonArray UserDatabase::usageProfiles() const
{
    QJsonArray result;
    QSqlQuery query(db_);
    if (!query.exec(QStringLiteral("SELECT profile_id, name, daily_limit_minutes, weekly_limit_minutes, "
                                   "monthly_limit_minutes FROM usage_profiles ORDER BY name COLLATE NOCASE")))
        return result;
    while (query.next()) {
        QJsonObject profile{{"profileId", query.value(0).toLongLong()},
                            {"name", query.value(1).toString()}};
        const QStringList fields = {QStringLiteral("dailyLimitMinutes"),
                                    QStringLiteral("weeklyLimitMinutes"),
                                    QStringLiteral("monthlyLimitMinutes")};
        for (int i = 0; i < fields.size(); ++i) {
            profile.insert(fields.at(i), query.value(i + 2).isNull()
                           ? QJsonValue(QJsonValue::Null)
                           : QJsonValue(query.value(i + 2).toLongLong()));
        }
        result.append(profile);
    }
    return result;
}

bool UserDatabase::createUsageProfile(const QJsonObject &profile, qint64 *profileId,
                                      QString *error)
{
    const QString name = profile.value(QStringLiteral("name")).toString().trimmed();
    if (name.isEmpty() || name.size() > 80) {
        if (error) *error = QStringLiteral("El nombre del perfil es obligatorio y no puede superar 80 caracteres.");
        return false;
    }
    qint64 daily = -1, weekly = -1, monthly = -1;
    if (!validatedUsageLimit(profile, QStringLiteral("dailyLimitMinutes"), 1440, &daily, error)
            || !validatedUsageLimit(profile, QStringLiteral("weeklyLimitMinutes"), 10080, &weekly, error)
            || !validatedUsageLimit(profile, QStringLiteral("monthlyLimitMinutes"), 44640, &monthly, error))
        return false;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("INSERT INTO usage_profiles(name, daily_limit_minutes, weekly_limit_minutes, "
                                 "monthly_limit_minutes, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)"));
    query.addBindValue(name);
    query.addBindValue(daily >= 0 ? QVariant(daily) : QVariant());
    query.addBindValue(weekly >= 0 ? QVariant(weekly) : QVariant());
    query.addBindValue(monthly >= 0 ? QVariant(monthly) : QVariant());
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    query.addBindValue(now);
    query.addBindValue(now);
    if (!query.exec()) {
        if (error) *error = query.lastError().text().contains(QStringLiteral("UNIQUE"), Qt::CaseInsensitive)
                ? QStringLiteral("Ya existe un perfil con ese nombre.") : queryError(query);
        return false;
    }
    if (profileId) *profileId = query.lastInsertId().toLongLong();
    return true;
}

bool UserDatabase::updateUsageProfile(qint64 profileId, const QJsonObject &profile,
                                      QString *error)
{
    const QString name = profile.value(QStringLiteral("name")).toString().trimmed();
    if (profileId <= 0 || name.isEmpty() || name.size() > 80) {
        if (error) *error = QStringLiteral("El nombre del perfil es obligatorio y no puede superar 80 caracteres.");
        return false;
    }
    qint64 daily = -1, weekly = -1, monthly = -1;
    if (!validatedUsageLimit(profile, QStringLiteral("dailyLimitMinutes"), 1440, &daily, error)
            || !validatedUsageLimit(profile, QStringLiteral("weeklyLimitMinutes"), 10080, &weekly, error)
            || !validatedUsageLimit(profile, QStringLiteral("monthlyLimitMinutes"), 44640, &monthly, error))
        return false;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("UPDATE usage_profiles SET name = ?, daily_limit_minutes = ?, "
                                 "weekly_limit_minutes = ?, monthly_limit_minutes = ?, updated_at = ? "
                                 "WHERE profile_id = ?"));
    query.addBindValue(name);
    query.addBindValue(daily >= 0 ? QVariant(daily) : QVariant());
    query.addBindValue(weekly >= 0 ? QVariant(weekly) : QVariant());
    query.addBindValue(monthly >= 0 ? QVariant(monthly) : QVariant());
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    query.addBindValue(profileId);
    if (!query.exec() || query.numRowsAffected() != 1) {
        if (error) *error = query.lastError().text().contains(QStringLiteral("UNIQUE"), Qt::CaseInsensitive)
                ? QStringLiteral("Ya existe un perfil con ese nombre.")
                : (query.lastError().text().isEmpty() ? QStringLiteral("No se encontró el perfil.") : queryError(query));
        return false;
    }
    return true;
}

bool UserDatabase::deleteUsageProfile(qint64 profileId, QString *error)
{
    QSqlQuery assigned(db_);
    assigned.prepare(QStringLiteral("SELECT 1 FROM users WHERE usage_profile_id = ? LIMIT 1"));
    assigned.addBindValue(profileId);
    if (!assigned.exec()) {
        if (error) *error = queryError(assigned);
        return false;
    }
    if (assigned.next()) {
        if (error) *error = QStringLiteral("No se puede eliminar un perfil asignado a usuarios.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("DELETE FROM usage_profiles WHERE profile_id = ?"));
    query.addBindValue(profileId);
    if (!query.exec() || query.numRowsAffected() != 1) {
        if (error) *error = queryError(query).isEmpty() ? QStringLiteral("No se encontró el perfil.") : queryError(query);
        return false;
    }
    return true;
}

qint64 UserDatabase::usageSeconds(const QString &userId, qint64 periodStart,
                                  qint64 periodEnd, qint64 now,
                                  qint64 additionalStart, qint64 additionalEnd) const
{
    QList<QPair<qint64, qint64>> intervals;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT started_at, ended_at FROM radio_usage_sessions "
                                 "WHERE user_id = ? AND started_at < ? "
                                 "AND (ended_at IS NULL OR ended_at > ?)"));
    query.addBindValue(normalizedUserId(userId));
    query.addBindValue(periodEnd);
    query.addBindValue(periodStart);
    if (!query.exec()) return -1;
    while (query.next()) {
        const qint64 start = qMax(periodStart, query.value(0).toLongLong());
        const qint64 end = qMin(periodEnd, query.value(1).isNull() ? now : query.value(1).toLongLong());
        if (end > start) intervals.append({start, end});
    }
    if (query.lastError().isValid()) return -1;
    query.finish();
    query.prepare(QStringLiteral("SELECT starts_at, ends_at FROM radio_reservations "
                                 "WHERE user_id = ? AND status = 'confirmed' "
                                 "AND starts_at < ? AND ends_at > ?"));
    query.addBindValue(normalizedUserId(userId));
    query.addBindValue(periodEnd);
    query.addBindValue(periodStart);
    if (!query.exec()) return -1;
    while (query.next()) {
        const qint64 start = qMax(periodStart, query.value(0).toLongLong());
        const qint64 end = qMin(periodEnd, query.value(1).toLongLong());
        if (end > start) intervals.append({start, end});
    }
    if (additionalEnd > additionalStart) {
        const qint64 start = qMax(periodStart, additionalStart);
        const qint64 end = qMin(periodEnd, additionalEnd);
        if (end > start) intervals.append({start, end});
    }
    std::sort(intervals.begin(), intervals.end(), [](const QPair<qint64, qint64> &a,
                                                     const QPair<qint64, qint64> &b) {
        return a.first < b.first;
    });
    qint64 total = 0;
    qint64 unionStart = 0, unionEnd = 0;
    bool active = false;
    for (const auto &interval : intervals) {
        if (!active) { unionStart = interval.first; unionEnd = interval.second; active = true; }
        else if (interval.first <= unionEnd) unionEnd = qMax(unionEnd, interval.second);
        else { total += unionEnd - unionStart; unionStart = interval.first; unionEnd = interval.second; }
    }
    if (active) total += unionEnd - unionStart;
    return total;
}

QJsonObject UserDatabase::usageStatus(const QString &userId) const
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QJsonObject status{{"found", false}, {"allowed", true}, {"profileId", QJsonValue(QJsonValue::Null)},
                       {"profileName", QStringLiteral("Sin límite")}};
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT p.profile_id, p.name, p.daily_limit_minutes, "
                                 "p.weekly_limit_minutes, p.monthly_limit_minutes "
                                 "FROM users u LEFT JOIN usage_profiles p ON p.profile_id = u.usage_profile_id "
                                 "WHERE u.user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec() || !query.next()) {
        status.insert(QStringLiteral("allowed"), false);
        status.insert(QStringLiteral("message"), QStringLiteral("No se ha encontrado la cuenta de usuario."));
        return status;
    }
    status.insert(QStringLiteral("found"), true);
    if (query.value(0).isNull()) return status;

    const QString profileName = query.value(1).toString();
    status.insert(QStringLiteral("profileId"), query.value(0).toLongLong());
    status.insert(QStringLiteral("profileName"), profileName);
    const QDateTime localNow = QDateTime::fromSecsSinceEpoch(now, Qt::LocalTime);
    const QDate date = localNow.date();
    const QDate weekStart = date.addDays(1 - date.dayOfWeek());
    const QList<QPair<QString, QDate>> starts = {
        {QStringLiteral("daily"), date},
        {QStringLiteral("weekly"), weekStart},
        {QStringLiteral("monthly"), QDate(date.year(), date.month(), 1)}
    };
    const QStringList titles = {QStringLiteral("diario"), QStringLiteral("semanal"), QStringLiteral("mensual")};
    const qint64 limits[] = {query.value(2).isNull() ? -1 : query.value(2).toLongLong() * 60,
                             query.value(3).isNull() ? -1 : query.value(3).toLongLong() * 60,
                             query.value(4).isNull() ? -1 : query.value(4).toLongLong() * 60};
    for (int i = 0; i < starts.size(); ++i) {
        const QDateTime periodStart(starts.at(i).second, QTime(0, 0), Qt::LocalTime);
        QDate nextDate = starts.at(i).second;
        if (i == 0) nextDate = nextDate.addDays(1);
        else if (i == 1) nextDate = nextDate.addDays(7);
        else nextDate = nextDate.addMonths(1);
        const QDateTime periodEnd(nextDate, QTime(0, 0), Qt::LocalTime);
        const QString periodKey = starts.at(i).first;
        QSqlQuery resetQuery(db_);
        resetQuery.prepare(QStringLiteral("SELECT reset_at FROM radio_usage_resets WHERE user_id = ? AND period = ?"));
        resetQuery.addBindValue(normalizedUserId(userId));
        resetQuery.addBindValue(periodKey);
        if (!resetQuery.exec()) {
            status.insert(QStringLiteral("allowed"), false);
            status.insert(QStringLiteral("message"), QStringLiteral("No se puede comprobar el tiempo autorizado. Inténtalo de nuevo."));
            break;
        }
        const bool hasReset = resetQuery.next();
        const qint64 resetAt = hasReset ? resetQuery.value(0).toLongLong() : 0;
        const qint64 effectiveStart = qMax(periodStart.toSecsSinceEpoch(), resetAt);
        const qint64 used = usageSeconds(userId, effectiveStart,
                                         periodEnd.toSecsSinceEpoch(), now);
        if (used < 0) {
            status.insert(QStringLiteral("allowed"), false);
            status.insert(QStringLiteral("message"), QStringLiteral("No se puede comprobar el tiempo autorizado. Inténtalo de nuevo.") );
            break;
        }
        const qint64 limit = limits[i];
        QJsonObject periodStatus{{"limitMinutes", limit < 0 ? QJsonValue(QJsonValue::Null)
                                                       : QJsonValue(limit / 60)},
                           {"usedSeconds", used},
                           {"resetAt", hasReset ? QJsonValue(resetAt) : QJsonValue(QJsonValue::Null)},
                           {"remainingSeconds", limit < 0 ? QJsonValue(QJsonValue::Null)
                                                           : QJsonValue(qMax<qint64>(0, limit - used))}};
        status.insert(periodKey, periodStatus);
        if (limit >= 0 && used >= limit && status.value(QStringLiteral("allowed")).toBool()) {
            status.insert(QStringLiteral("allowed"), false);
            status.insert(QStringLiteral("message"),
                           QStringLiteral("Has agotado el tiempo autorizado %1 del perfil «%2».")
                           .arg(titles.at(i), profileName));
        }
    }
    return status;
}

bool UserDatabase::resetUsagePeriod(const QString &userId, const QString &period,
                                    QString *error)
{
    const QStringList validPeriods = {QStringLiteral("daily"), QStringLiteral("weekly"),
                                      QStringLiteral("monthly")};
    const QString id = normalizedUserId(userId);
    if (id.isEmpty() || !validPeriods.contains(period)) {
        if (error) *error = QStringLiteral("El periodo de uso no es válido.");
        return false;
    }
    const QJsonObject usage = usageStatus(id);
    if (!usage.value(QStringLiteral("found")).toBool()) {
        if (error) *error = QStringLiteral("No se ha encontrado la cuenta de usuario.");
        return false;
    }
    if (!usage.value(period).isObject()) {
        if (error) *error = QStringLiteral("El usuario no tiene un límite asignado para ese periodo.");
        return false;
    }
    const QJsonObject periodStatus = usage.value(period).toObject();
    if (periodStatus.value(QStringLiteral("limitMinutes")).isNull()) {
        if (error) *error = QStringLiteral("El perfil asignado no tiene límite para ese periodo.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral(
        "INSERT INTO radio_usage_resets(user_id, period, reset_at) VALUES(?, ?, ?) "
        "ON CONFLICT(user_id, period) DO UPDATE SET reset_at = excluded.reset_at"));
    query.addBindValue(id);
    query.addBindValue(period);
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec()) {
        if (error) *error = queryError(query);
        return false;
    }
    return true;
}

QString UserDatabase::startUsageSession(const QString &userId, QJsonObject *status,
                                       QString *error)
{
    if (!db_.transaction()) {
        if (error) *error = db_.lastError().text();
        return QString();
    }
    QJsonObject current = usageStatus(userId);
    if (!current.value(QStringLiteral("allowed")).toBool()) {
        if (status) *status = current;
        db_.rollback();
        if (error) *error = current.value(QStringLiteral("message")).toString();
        return QString();
    }
    const QString id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("INSERT INTO radio_usage_sessions(session_id, user_id, started_at, ended_at) "
                                 "VALUES(?, ?, ?, NULL)"));
    query.addBindValue(id);
    query.addBindValue(normalizedUserId(userId));
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec() || !db_.commit()) {
        if (error) *error = queryError(query).isEmpty() ? db_.lastError().text() : queryError(query);
        db_.rollback();
        return QString();
    }
    QSqlQuery cleanup(db_);
    cleanup.prepare(QStringLiteral("DELETE FROM radio_usage_sessions WHERE ended_at IS NOT NULL AND ended_at < ?"));
    cleanup.addBindValue(QDateTime::currentSecsSinceEpoch() - 90 * 24 * 60 * 60);
    cleanup.exec();
    if (status) *status = usageStatus(userId);
    return id;
}

void UserDatabase::endUsageSession(const QString &sessionId)
{
    endUsageSession(sessionId, QDateTime::currentSecsSinceEpoch());
}

void UserDatabase::endUsageSession(const QString &sessionId, qint64 endedAt)
{
    if (sessionId.isEmpty()) return;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("UPDATE radio_usage_sessions SET ended_at = ? "
                                 "WHERE session_id = ? AND ended_at IS NULL"));
    query.addBindValue(endedAt);
    query.addBindValue(sessionId);
    query.exec();
}

QString UserDatabase::activeReservationOwner(qint64 now) const
{
    return activeReservation(now).value(QStringLiteral("userId")).toString();
}

QJsonObject UserDatabase::activeReservation(qint64 now) const
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT r.reservation_id, r.user_id, u.first_name, u.last_name, "
                                 "r.starts_at, r.ends_at FROM radio_reservations r "
                                 "JOIN users u ON u.user_id = r.user_id "
                                 "WHERE r.status = 'confirmed' AND r.starts_at <= ? AND r.ends_at > ? "
                                 "ORDER BY r.starts_at LIMIT 1"));
    query.addBindValue(now);
    query.addBindValue(now);
    if (!query.exec() || !query.next()) return QJsonObject();
    const QString name = (query.value(2).toString() + QLatin1Char(' ') + query.value(3).toString()).trimmed();
    return QJsonObject{{"id", query.value(0).toLongLong()},
                       {"userId", query.value(1).toString()},
                       {"name", name},
                       {"startsAt", query.value(4).toLongLong()},
                       {"endsAt", query.value(5).toLongLong()},
                       {"isActive", true}};
}

QJsonArray UserDatabase::upcomingReservations(qint64 now, qint64 through) const
{
    QJsonArray reservations;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT r.reservation_id, r.user_id, u.first_name, u.last_name, "
                                 "r.starts_at, r.ends_at FROM radio_reservations r "
                                 "JOIN users u ON u.user_id = r.user_id "
                                 "WHERE r.status = 'confirmed' AND r.starts_at < ? AND r.ends_at > ? "
                                 "ORDER BY r.starts_at ASC"));
    query.addBindValue(through);
    query.addBindValue(now);
    if (!query.exec()) return reservations;
    while (query.next()) {
        const qint64 startsAt = query.value(4).toLongLong();
        const qint64 endsAt = query.value(5).toLongLong();
        const QString name = (query.value(2).toString() + QLatin1Char(' ') + query.value(3).toString()).trimmed();
        reservations.append(QJsonObject{{"id", query.value(0).toLongLong()},
                                        {"userId", query.value(1).toString()},
                                        {"name", name},
                                        {"startsAt", startsAt},
                                        {"endsAt", endsAt},
                                        {"isActive", startsAt <= now && endsAt > now}});
    }
    return reservations;
}

bool UserDatabase::isAdministrator(const QString &userId) const
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT is_admin FROM users WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    return query.exec() && query.next() && query.value(0).toBool();
}

QJsonArray UserDatabase::reservations(const QString &userId) const
{
    QJsonArray result;
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("SELECT reservation_id, starts_at, ends_at, status FROM radio_reservations "
                                 "WHERE user_id = ? ORDER BY starts_at DESC"));
    query.addBindValue(normalizedUserId(userId));
    if (!query.exec()) return result;
    while (query.next()) {
        const qint64 start = query.value(1).toLongLong();
        const qint64 end = query.value(2).toLongLong();
        result.append(QJsonObject{{"id", query.value(0).toLongLong()}, {"startsAt", start},
                                  {"endsAt", end}, {"durationMinutes", (end - start) / 60},
                                  {"status", query.value(3).toString()}});
    }
    return result;
}

bool UserDatabase::reservationWithinUsageLimits(const QString &userId, qint64 startsAt,
                                                qint64 endsAt, QString *error) const
{
    QSqlQuery profileQuery(db_);
    profileQuery.prepare(QStringLiteral("SELECT p.daily_limit_minutes, p.weekly_limit_minutes, "
                                        "p.monthly_limit_minutes FROM users u "
                                        "LEFT JOIN usage_profiles p ON p.profile_id = u.usage_profile_id "
                                        "WHERE u.user_id = ?"));
    profileQuery.addBindValue(normalizedUserId(userId));
    if (!profileQuery.exec() || !profileQuery.next()) {
        if (error) *error = QStringLiteral("No se ha encontrado la cuenta de usuario.");
        return false;
    }
    const QVariant values[] = {profileQuery.value(0), profileQuery.value(1), profileQuery.value(2)};
    const QString keys[] = {QStringLiteral("daily"), QStringLiteral("weekly"), QStringLiteral("monthly")};
    const QString labels[] = {QStringLiteral("diario"), QStringLiteral("semanal"), QStringLiteral("mensual")};
    const QDateTime localStart = QDateTime::fromSecsSinceEpoch(startsAt, Qt::LocalTime);
    for (int kind = 0; kind < 3; ++kind) {
        if (values[kind].isNull()) continue;
        const qint64 limit = values[kind].toLongLong() * 60;
        QDate periodDate = localStart.date();
        QDateTime periodStart;
        while (true) {
            QDate baseDate = periodDate;
            if (kind == 1) baseDate = periodDate.addDays(1 - periodDate.dayOfWeek());
            else if (kind == 2) baseDate = QDate(periodDate.year(), periodDate.month(), 1);
            periodStart = QDateTime(baseDate, QTime(0, 0), Qt::LocalTime);
            QDate nextDate = baseDate;
            if (kind == 0) nextDate = nextDate.addDays(1);
            else if (kind == 1) nextDate = nextDate.addDays(7);
            else nextDate = nextDate.addMonths(1);
            const QDateTime periodEnd(nextDate, QTime(0, 0), Qt::LocalTime);
            const qint64 periodStartSec = periodStart.toSecsSinceEpoch();
            const qint64 periodEndSec = periodEnd.toSecsSinceEpoch();
            const qint64 clippedStart = qMax(startsAt, periodStartSec);
            const qint64 clippedEnd = qMin(endsAt, periodEndSec);
            QSqlQuery reset(db_);
            reset.prepare(QStringLiteral("SELECT reset_at FROM radio_usage_resets WHERE user_id = ? AND period = ?"));
            reset.addBindValue(normalizedUserId(userId));
            reset.addBindValue(keys[kind]);
            if (!reset.exec()) {
                if (error) *error = QStringLiteral("No se puede comprobar el tiempo autorizado.");
                return false;
            }
            const qint64 effectiveStart = qMax(periodStartSec, reset.next() ? reset.value(0).toLongLong() : 0);
            const qint64 used = usageSeconds(userId, effectiveStart, periodEndSec,
                                             QDateTime::currentSecsSinceEpoch(), clippedStart, clippedEnd);
            if (used < 0 || used > limit) {
                if (error) *error = QStringLiteral("La reserva excede el tiempo autorizado %1 disponible.").arg(labels[kind]);
                return false;
            }
            if (periodEndSec >= endsAt) break;
            periodDate = nextDate;
        }
    }
    return true;
}

bool UserDatabase::createReservation(const QString &userId, qint64 startsAt, qint64 endsAt,
                                     qint64 *reservationId, QString *error)
{
    const QString id = normalizedUserId(userId);
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (id.isEmpty() || startsAt <= now || endsAt <= startsAt || startsAt % 60 || endsAt % 60) {
        if (error) *error = QStringLiteral("El intervalo debe ser futuro, válido y comenzar y terminar en un minuto exacto.");
        return false;
    }
    if (!db_.transaction()) {
        if (error) *error = db_.lastError().text();
        return false;
    }
    QSqlQuery userQuery(db_);
    userQuery.prepare(QStringLiteral("SELECT max_reservation_minutes FROM users WHERE user_id = ?"));
    userQuery.addBindValue(id);
    if (!userQuery.exec() || !userQuery.next()) {
        if (error) *error = QStringLiteral("No se ha encontrado la cuenta de usuario.");
        db_.rollback();
        return false;
    }
    const qint64 maxMinutes = userQuery.value(0).toLongLong();
    const qint64 duration = endsAt - startsAt;
    if (maxMinutes <= 0) {
        if (error) *error = QStringLiteral("Tu perfil no permite realizar reservas.");
        db_.rollback();
        return false;
    }
    if (duration > maxMinutes * 60) {
        if (error) *error = QStringLiteral("La duración supera el tiempo máximo por reserva de tu perfil.");
        db_.rollback();
        return false;
    }
    QSqlQuery conflict(db_);
    conflict.prepare(QStringLiteral("SELECT 1 FROM radio_reservations WHERE status = 'confirmed' "
                                    "AND starts_at < ? AND ends_at > ? LIMIT 1"));
    conflict.addBindValue(endsAt);
    conflict.addBindValue(startsAt);
    if (!conflict.exec()) {
        if (error) *error = queryError(conflict);
        db_.rollback();
        return false;
    }
    if (conflict.next()) {
        if (error) *error = QStringLiteral("Ese intervalo ya está reservado.");
        db_.rollback();
        return false;
    }
    if (!reservationWithinUsageLimits(id, startsAt, endsAt, error)) {
        db_.rollback();
        return false;
    }
    QSqlQuery insert(db_);
    insert.prepare(QStringLiteral("INSERT INTO radio_reservations(user_id, starts_at, ends_at, created_at) "
                                  "VALUES(?, ?, ?, ?)"));
    insert.addBindValue(id);
    insert.addBindValue(startsAt);
    insert.addBindValue(endsAt);
    insert.addBindValue(now);
    if (!insert.exec() || !db_.commit()) {
        if (error) *error = queryError(insert).isEmpty() ? db_.lastError().text() : queryError(insert);
        db_.rollback();
        return false;
    }
    if (reservationId) *reservationId = insert.lastInsertId().toLongLong();
    return true;
}

bool UserDatabase::cancelReservation(const QString &userId, qint64 reservationId, QString *error)
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("UPDATE radio_reservations SET status = 'cancelled' "
                                 "WHERE reservation_id = ? AND user_id = ? AND status = 'confirmed' AND starts_at > ?"));
    query.addBindValue(reservationId);
    query.addBindValue(normalizedUserId(userId));
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec() || query.numRowsAffected() != 1) {
        if (error) *error = QStringLiteral("Solo se pueden cancelar reservas futuras confirmadas.");
        return false;
    }
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

#include "userdatabase.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>
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
            "created_at INTEGER NOT NULL)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    if (!query.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "token_hash BLOB PRIMARY KEY, "
            "user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, "
            "expires_at INTEGER NOT NULL)"))) {
        if (error) *error = queryError(query);
        return false;
    }
    query.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id)"));
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
    query.prepare(QStringLiteral("SELECT user_id, password_hash, is_admin, must_change_password "
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
        "SELECT u.user_id, u.is_admin, u.must_change_password, s.expires_at "
        "FROM sessions s JOIN users u ON u.user_id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?"));
    query.addBindValue(tokenHash(token));
    query.addBindValue(QDateTime::currentSecsSinceEpoch());
    if (!query.exec() || !query.next()) return user;
    user.userId = query.value(0).toString();
    user.isAdmin = query.value(1).toInt() != 0;
    user.mustChangePassword = query.value(2).toInt() != 0;
    user.sessionExpiresAt = query.value(3).toLongLong();
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

bool UserDatabase::createUser(const QString &userId, const QString &password,
                              bool makeAdmin, QString *error)
{
    const QString id = normalizedUserId(userId);
    static const QRegularExpression validId(QStringLiteral("^[A-Z0-9][A-Z0-9._-]{0,31}$"));
    if (!validId.match(id).hasMatch()) {
        if (error) *error = QStringLiteral("User ID must use 1-32 letters, numbers, dots, underscores, or hyphens.");
        return false;
    }
    if (!validPassword(password)) {
        if (error) *error = QStringLiteral("Password must be at least 12 characters and no more than 256 UTF-8 bytes.");
        return false;
    }
    QSqlQuery query(db_);
    query.prepare(QStringLiteral(
        "INSERT INTO users(user_id, password_hash, is_admin, must_change_password, created_at) "
        "VALUES(?, ?, ?, 1, ?)"));
    query.addBindValue(id);
    query.addBindValue(passwordHash(password));
    query.addBindValue(makeAdmin ? 1 : 0);
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
    if (!query.exec(QStringLiteral("SELECT user_id, is_admin, must_change_password "
                                   "FROM users ORDER BY user_id COLLATE NOCASE")))
        return result;
    while (query.next()) {
        result.append(QJsonObject{{"userId", query.value(0).toString()},
                                  {"isAdmin", query.value(1).toInt() != 0},
                                  {"mustChangePassword", query.value(2).toInt() != 0}});
    }
    return result;
}

void UserDatabase::revokeSessions(const QString &userId)
{
    QSqlQuery query(db_);
    query.prepare(QStringLiteral("DELETE FROM sessions WHERE user_id = ?"));
    query.addBindValue(normalizedUserId(userId));
    query.exec();
}

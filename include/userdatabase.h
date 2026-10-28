#ifndef USERDATABASE_H
#define USERDATABASE_H

#include <QJsonArray>
#include <QJsonObject>
#include <QSqlDatabase>
#include <QString>

struct AuthUser {
    QString userId;
    QString operationalProfile = QStringLiteral("licensed");
    bool isAdmin = false;
    bool mustChangePassword = false;
    qint64 sessionExpiresAt = 0;
    bool authenticated = false;
};

class UserDatabase
{
public:
    UserDatabase() = default;
    ~UserDatabase();
    UserDatabase(const UserDatabase &) = delete;
    UserDatabase &operator=(const UserDatabase &) = delete;

    bool open(const QString &path, QString *error = nullptr);
    bool verifyCredentials(const QString &userId, const QString &password,
                           AuthUser *user) const;
    bool createSession(const QString &userId, QString *token,
                       qint64 *expiresAt = nullptr);
    AuthUser userForSession(const QString &token) const;
    bool changePassword(const QString &userId, const QString &password,
                        QString *error = nullptr);
    bool createUser(const QJsonObject &profile, const QString &password,
                    bool makeAdmin, QString *error = nullptr);
    bool promoteUser(const QString &userId, QString *error = nullptr);
    QJsonArray users() const;
    QJsonObject profile(const QString &userId) const;
    bool updateOwnProfile(const QString &userId, const QJsonObject &profile,
                          QString *newUserId, QString *error = nullptr);
    bool updateAdminUser(const QString &userId, const QJsonObject &profile,
                         QString *newUserId, QString *error = nullptr);
    bool canTransmit(const QString &userId) const;
    void revokeSessions(const QString &userId);

    static QString normalizedUserId(const QString &userId);
    static bool validPassword(const QString &password);

private:
    bool createSchema(QString *error);
    bool migrateSchema(QString *error);
    bool seedInitialAdmin(QString *error);
    static QString passwordHash(const QString &password);
    static bool passwordMatches(const QString &password, const QString &storedHash);
    static QByteArray tokenHash(const QString &token);
    bool updateProfile(const QString &userId, const QJsonObject &profile,
                       bool administrator, QString *newUserId, QString *error);

    QSqlDatabase db_;
    QString connectionName_;
};

#endif // USERDATABASE_H

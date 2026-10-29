#ifndef USERDATABASE_H
#define USERDATABASE_H

#include <QJsonArray>
#include <QJsonObject>
#include <QSqlDatabase>
#include <QString>

struct AuthUser {
    QString userId;
    QString operationalProfile = QStringLiteral("licensed");
    qint64 usageProfileId = 0;
    QString usageProfileName;
    qint64 maxReservationMinutes = 0;
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
    QJsonObject reservationStatus(const QString &userId) const;
    QJsonArray usageProfiles() const;
    bool createUsageProfile(const QJsonObject &profile, qint64 *profileId,
                            QString *error = nullptr);
    bool updateUsageProfile(qint64 profileId, const QJsonObject &profile,
                            QString *error = nullptr);
    bool deleteUsageProfile(qint64 profileId, QString *error = nullptr);
    QJsonObject usageStatus(const QString &userId) const;
    bool resetUsagePeriod(const QString &userId, const QString &period,
                          QString *error = nullptr);
    QString startUsageSession(const QString &userId, QJsonObject *status,
                              QString *error = nullptr);
    void endUsageSession(const QString &sessionId);
    void endUsageSession(const QString &sessionId, qint64 endedAt);
    QString activeReservationOwner(qint64 now) const;
    QJsonObject activeReservation(qint64 now) const;
    QJsonObject missedReservation(const QString &userId, qint64 now) const;
    int processExpiredReservations(qint64 now);
    QJsonArray upcomingReservations(qint64 now, qint64 through) const;
    bool isAdministrator(const QString &userId) const;
    QJsonArray reservations(const QString &userId) const;
    bool createReservation(const QString &userId, qint64 startsAt, qint64 endsAt,
                           qint64 *reservationId, QString *error = nullptr);
    bool cancelReservation(const QString &userId, qint64 reservationId,
                           QString *error = nullptr);
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
    bool validateUsageAssignment(const QJsonValue &profileId, qint64 *id,
                                 QString *error) const;
    bool reservationWithinUsageLimits(const QString &userId, qint64 startsAt,
                                      qint64 endsAt, QString *error) const;
    qint64 usageSeconds(const QString &userId, qint64 periodStart,
                        qint64 periodEnd, qint64 now,
                        qint64 additionalStart = 0,
                        qint64 additionalEnd = 0) const;

    QSqlDatabase db_;
    QString connectionName_;
};

#endif // USERDATABASE_H

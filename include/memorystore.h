#ifndef MEMORYSTORE_H
#define MEMORYSTORE_H

#include <QJsonObject>
#include <QList>
#include <QString>

// One channel as wfweb stores it for a radio that cannot store one itself.
//
// Deliberately smaller than memoryType: a local channel is replayed onto the
// VFO as a plain frequency + mode + filter, so there is nowhere to put tone,
// duplex or split. Radios that can hold those in a real channel never reach
// this store — they go through funcMemoryContents instead.
struct localMemory {
    int     channel = 0;
    qint64  frequency = 0;   // Hz
    quint8  modeReg = 0;     // rig mode register, as in rigCaps.modes
    quint8  filter = 1;      // FIL1 unless the rig said otherwise
    QString name;

    QJsonObject toJson() const;
    static localMemory fromJson(int channel, const QJsonObject &o);
};

// wfweb's own memory channels, for radios whose CI-V has no way to read a
// channel back (IC-718, IC-706/706MK2G — see issue #114).
//
// One JSON file holds every rig's list, keyed by model name, so swapping
// radios doesn't mix their channels up. Small by construction: a rig file's
// Memories count caps it around 100 entries, so the whole document stays in
// memory and every mutation rewrites it. No paging, no index.
class MemoryStore {
public:
    // Loads path if it exists; a missing or unreadable file starts empty
    // rather than failing, so a fresh install just works. Returns false only
    // when the file exists but could not be parsed — the caller logs it and
    // carries on with an empty store rather than dropping the feature.
    bool open(const QString &path);

    // Which rig's list the accessors below operate on. Empty model = no rig,
    // and every read comes back empty.
    void setRig(const QString &model);
    QString rig() const { return rig_; }

    QList<localMemory> all() const;            // ascending by channel
    bool contains(int channel) const;
    localMemory get(int channel) const;

    // Each of these persists immediately — there is no separate flush, and a
    // caller that forgets one cannot silently lose a channel. Return false if
    // the write failed, with the in-memory copy already updated so the UI
    // stays consistent with what the user just did.
    bool set(const localMemory &m);
    bool rename(int channel, const QString &name);
    bool remove(int channel);

    static const int maxNameLength = 32;

private:
    QJsonObject rigObject() const;
    void setRigObject(const QJsonObject &o);
    bool save();

    QString     path_;
    QString     rig_;
    QJsonObject doc_;
};

#endif // MEMORYSTORE_H

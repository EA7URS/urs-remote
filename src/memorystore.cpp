#include "memorystore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>

#include "logcategories.h"

// Document shape:
//
//   { "version": 1,
//     "rigs": { "IC-718": { "1": { "freq": 14074000, "mode": 1,
//                                  "filter": 1, "name": "FT8 20m" } } } }
//
// Channel numbers are object keys rather than array indices so a sparse list
// (channels 1, 7, 40) costs nothing and the file stays readable by hand.
static const char *KEY_VERSION = "version";
static const char *KEY_RIGS    = "rigs";

QJsonObject localMemory::toJson() const
{
    QJsonObject o;
    o["freq"] = frequency;
    o["mode"] = int(modeReg);
    o["filter"] = int(filter);
    if (!name.isEmpty()) o["name"] = name;
    return o;
}

localMemory localMemory::fromJson(int channel, const QJsonObject &o)
{
    localMemory m;
    m.channel = channel;
    m.frequency = qint64(o["freq"].toDouble(0));
    m.modeReg = quint8(o["mode"].toInt(0));
    // A file written by hand could leave the filter out entirely; FIL1 is the
    // same default the rig path uses.
    int fil = o["filter"].toInt(1);
    m.filter = quint8(fil > 0 ? fil : 1);
    m.name = o["name"].toString().left(MemoryStore::maxNameLength);
    return m;
}

bool MemoryStore::open(const QString &path)
{
    path_ = path;
    doc_ = QJsonObject();
    doc_[KEY_VERSION] = 1;
    doc_[KEY_RIGS] = QJsonObject();

    QFile f(path_);
    if (!f.exists()) return true;          // fresh install, nothing to load
    if (!f.open(QIODevice::ReadOnly)) {
        qCWarning(logWebServer) << "MemoryStore: cannot read" << path_ << f.errorString();
        return false;
    }
    QJsonParseError err;
    const QJsonDocument parsed = QJsonDocument::fromJson(f.readAll(), &err);
    f.close();
    if (err.error != QJsonParseError::NoError || !parsed.isObject()) {
        // Keep the unreadable file rather than overwriting it — the user's
        // channels may still be recoverable by hand. Saving later replaces it.
        qCWarning(logWebServer) << "MemoryStore:" << path_ << "is not valid JSON:"
                                << err.errorString();
        return false;
    }
    const QJsonObject o = parsed.object();
    if (o.contains(KEY_RIGS) && o[KEY_RIGS].isObject()) {
        doc_[KEY_RIGS] = o[KEY_RIGS];
    }
    int n = 0;
    const QJsonObject rigs = doc_[KEY_RIGS].toObject();
    for (auto it = rigs.constBegin(); it != rigs.constEnd(); ++it) {
        n += it.value().toObject().size();
    }
    qCInfo(logWebServer) << "MemoryStore: loaded" << n << "channels for"
                         << rigs.size() << "rig(s) from" << path_;
    return true;
}

void MemoryStore::setRig(const QString &model)
{
    rig_ = model;
}

QJsonObject MemoryStore::rigObject() const
{
    if (rig_.isEmpty()) return QJsonObject();
    return doc_[KEY_RIGS].toObject().value(rig_).toObject();
}

void MemoryStore::setRigObject(const QJsonObject &o)
{
    if (rig_.isEmpty()) return;
    QJsonObject rigs = doc_[KEY_RIGS].toObject();
    if (o.isEmpty()) rigs.remove(rig_);
    else rigs[rig_] = o;
    doc_[KEY_RIGS] = rigs;
}

QList<localMemory> MemoryStore::all() const
{
    QList<localMemory> out;
    const QJsonObject o = rigObject();
    for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
        bool ok = false;
        const int ch = it.key().toInt(&ok);
        if (!ok || !it.value().isObject()) continue;
        out.append(localMemory::fromJson(ch, it.value().toObject()));
    }
    // Object keys come back in insertion order, and the panel wants channels
    // in numeric order — "10" must not sort before "2".
    std::sort(out.begin(), out.end(),
              [](const localMemory &a, const localMemory &b) { return a.channel < b.channel; });
    return out;
}

bool MemoryStore::contains(int channel) const
{
    return rigObject().contains(QString::number(channel));
}

localMemory MemoryStore::get(int channel) const
{
    const QJsonObject o = rigObject();
    const QString key = QString::number(channel);
    if (!o.contains(key)) return localMemory();
    return localMemory::fromJson(channel, o[key].toObject());
}

bool MemoryStore::set(const localMemory &m)
{
    if (rig_.isEmpty()) return false;
    localMemory copy = m;
    copy.name = copy.name.trimmed().left(maxNameLength);
    QJsonObject o = rigObject();
    o[QString::number(m.channel)] = copy.toJson();
    setRigObject(o);
    return save();
}

bool MemoryStore::rename(int channel, const QString &name)
{
    if (rig_.isEmpty()) return false;
    QJsonObject o = rigObject();
    const QString key = QString::number(channel);
    if (!o.contains(key)) return false;
    QJsonObject entry = o[key].toObject();
    const QString trimmed = name.trimmed().left(maxNameLength);
    if (trimmed.isEmpty()) entry.remove("name");
    else entry["name"] = trimmed;
    o[key] = entry;
    setRigObject(o);
    return save();
}

bool MemoryStore::remove(int channel)
{
    if (rig_.isEmpty()) return false;
    QJsonObject o = rigObject();
    const QString key = QString::number(channel);
    if (!o.contains(key)) return false;
    o.remove(key);
    setRigObject(o);
    return save();
}

bool MemoryStore::save()
{
    if (path_.isEmpty()) return false;
    QDir().mkpath(QFileInfo(path_).absolutePath());
    // QSaveFile so an interrupted write can't truncate the existing channels.
    QSaveFile f(path_);
    if (!f.open(QIODevice::WriteOnly)) {
        qCWarning(logWebServer) << "MemoryStore: cannot write" << path_ << f.errorString();
        return false;
    }
    f.write(QJsonDocument(doc_).toJson(QJsonDocument::Indented));
    if (!f.commit()) {
        qCWarning(logWebServer) << "MemoryStore: commit failed for" << path_ << f.errorString();
        return false;
    }
    return true;
}

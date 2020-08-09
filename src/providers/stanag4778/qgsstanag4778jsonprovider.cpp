/***************************************************************************
    qgsstanag4778jsonprovider.h: Data provider for STANAG 4778 JSON
    ---------------------
    begin                : July 2020
    copyright            : (C) 2020 by Maxar Technologies, Inc.
    email                : michael dot leedahl at maxar.com

    Modification History
    ---------------------
    Michael Leedahl - July 2020: Initial Version

 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsstanag4778jsonprovider.h"
#include "qgsstanag4778jsonfeatureiterator.h"
#include "qgsapplication.h"
#include "qgsprojectstorageregistry.h"
#include "qgsjwe.h"
#include "qgsgeometry.h"
#include "qgsmultilinestring.h"
#include "qgsmultipolygon.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QByteArray>
#include <QString>

#define TEXT_PROVIDER_KEY QStringLiteral( "s4778j" )
#define TEXT_PROVIDER_DESCRIPTION QStringLiteral( "STANAG 4778 JSON data provider" )

QgsStanag4778JsonProvider::QgsStanag4778JsonProvider( QString const &message,
const StanagProviderOptions &providerOptions ) : QgsVectorDataProvider(message, providerOptions) {

  initDataTypes();
  parseFeatures(message, providerOptions.auth);
}

void QgsStanag4778JsonProvider::parseFeatures(const QString &message, const QgsAuthorizationSettings &auth) {

  mFields.clear();
  mFeatureCount = 0;
  FeatureContainer container;
  QList<FeatureContainer> features;
  QgsJwe *pJwe = nullptr;
  bool first = true;

  try {
    auto document = QJsonDocument::fromJson(message.toUtf8());
    if(document.isNull() || document.isArray()) {
      throw QgsException("Invalid STANAG JSON message received (MESSAGE).");
    }

    auto root = document.object();
    auto type = root.value("type");
    if((type.type() != QJsonValue::String) || (type.toString() != "STANAG4778")) {
      throw QgsException("Invalid STANAG JSON message received (TYPE).");
    }

    auto objectsValue = root.value("objects");
    if(objectsValue.type() != QJsonValue::Array) {
      throw QgsException("Invalid STANAG JSON message received (OBJECTS).");
    }

    auto objects = objectsValue.toArray();
    for(const auto &itemValue : objects) {
      if(itemValue.type() != QJsonValue::Object) {
        throw QgsException("Invalid STANAG JSON message received (ITEM).");
      }

      auto item = itemValue.toObject();
      auto dataValue = item.value("Data");
      if(dataValue.type() != QJsonValue::String) {
        throw QgsException("Invalid STANAG JSON message received (DATA).");
      }

      auto data = dataValue.toString();
      if(pJwe == nullptr) pJwe = new QgsJwe(auth, data);
      else pJwe->setEncryptedText(data);

      if(pJwe->errorCode() != QgsJwe::ErrorCode::NoError) {
        pushError(pJwe->errorMessage());
        continue;
      }

      QString decrypted = pJwe->message();
      if(pJwe->errorCode() != QgsJwe::ErrorCode::NoError) {
        pushError(pJwe->errorMessage());
        continue;
      }

      qDebug() << "QgsStanag4778JsonProvider::QgsStanag4778JsonProvider decrypted:\n" << decrypted;

      auto attributes = addNewFields(decrypted);
      extractWktType(decrypted);
      container = createFeature(decrypted, mFeatureCount, &attributes);
      parseGeometry(decrypted, &container, first);
      first = false;
      features.append(container);

      mFeatureCount++;
    }

    fixFeatures(features);

  } catch(QgsException ex) {
    pushError(ex.what());
  }

  if(pJwe != nullptr) delete pJwe;
}

void QgsStanag4778JsonProvider::parseGeometry(const QString &decrypted, FeatureContainer *pContainer, bool first) {
  auto document = QJsonDocument::fromJson(decrypted.toUtf8());
  if(document.isNull() || document.isArray()) {
    pushError("Invalid STANAG JSON message received (Geometry).");
    return;
  }

  auto root = document.object();
  auto geometryValue = root.value("geometry");
  if(geometryValue.type() != QJsonValue::Object) {
    pushError("Invalid STANAG JSON message received (Geometry Value).");
    return;
  }

  auto geometry = geometryValue.toObject();
  switch(mWkbType) {
    case QgsWkbTypes::Type::MultiLineString:
      extractMutiLineString(geometry, pContainer, first);
      break;

    case QgsWkbTypes::Type::Point:
      extractPoint(geometry, pContainer, first);
      break;

    case QgsWkbTypes::Type::MultiPolygon:
      extractMutiPolygon(geometry, pContainer, first);
      break;

    default:
      pushError("Application Error (WKB Type).");
      return;
  }
}

void QgsStanag4778JsonProvider::extractPoint(const QJsonObject &geometry, FeatureContainer *pContainer, bool first) {
  QByteArray wkt;
  auto coordinatesValue = geometry.value("coordinates");
  if(coordinatesValue.type() != QJsonValue::Array) {
    pushError("Invalid STANAG JSON message received (Coordinates).");
    return;
  }

  auto points = coordinatesValue.toArray();
  wkt.reserve(39);
  wkt.append("POINT (");
  auto longitudeValue = points[0];
  auto latitudeValue = points[1];
  if((longitudeValue.type() != QJsonValue::Double) || (latitudeValue.type() != QJsonValue::Double)) {
    pushError("Invalid STANAG JSON message received (Points).");
    return;
  }
  auto longitude = QByteArray::number(longitudeValue.toDouble());
  auto latitude = QByteArray::number(latitudeValue.toDouble());

  if(first) mExtent.set(longitude.toDouble(), latitude.toDouble(), longitude.toDouble(), latitude.toDouble());
  else {
    if(longitudeValue.toDouble() < mExtent.xMinimum()) mExtent.setXMinimum(longitudeValue.toDouble());
    if(longitudeValue.toBool() > mExtent.xMaximum()) mExtent.setXMaximum(longitudeValue.toDouble());
    if(latitudeValue.toDouble() < mExtent.yMinimum()) mExtent.setYMinimum(latitudeValue.toDouble());
    if(latitudeValue.toDouble() > mExtent.yMaximum()) mExtent.setYMaximum(latitudeValue.toDouble());
  }

  wkt.append(longitude).append(" ").append(latitude);
  wkt.append(")");
  QgsPoint *pPoint = new QgsPoint();
  if(!pPoint->fromWkt(wkt)) {
    pushError("Application Error (WKT Point).");
    return;
  }

  QgsGeometry result(pPoint);
  pContainer->mFeature.setGeometry(result);
}

void QgsStanag4778JsonProvider::extractMutiLineString(const QJsonObject &geometry, FeatureContainer *pContainer, bool first) {
  QByteArray wkt;
  auto coordinatesValue = geometry.value("coordinates");
  if(coordinatesValue.type() != QJsonValue::Array) {
    pushError("Invalid STANAG JSON message received (Coordinates).");
    return;
  }

  auto lines = coordinatesValue.toArray();
  wkt.reserve(18 + (lines.size() * 67));
  wkt.append("MULTILINESTRING ((");
  bool endLine = false;
  for(auto lineValue : lines) {
    if(lineValue.type() != QJsonValue::Array) {
      pushError("Invalid STANAG JSON message received (Lines).");
      return;
    }

    if(endLine) wkt.append("), (");
    else endLine = true;

    auto line = lineValue.toArray();
    bool addComma = false;
    for(auto pointsValue : line) {
      if(pointsValue.type() != QJsonValue::Array) {
        pushError("Invalid STANAG JSON message received (Line).");
        return;
      }

      if(addComma) wkt.append(", ");
      else addComma = true;

      auto point = pointsValue.toArray();
      auto longitudeValue = point[0];
      auto latitudeValue = point[1];
      if((longitudeValue.type() != QJsonValue::Double) || (latitudeValue.type() != QJsonValue::Double)) {
        pushError("Invalid STANAG JSON message received (Line Point).");
        return;
      }
      auto longitude = QByteArray::number(longitudeValue.toDouble());
      auto latitude = QByteArray::number(latitudeValue.toDouble());

      if(first) {
        mExtent.set(longitude.toDouble(), latitude.toDouble(), longitude.toDouble(), latitude.toDouble());
        first = false;

      } else {
        if(longitudeValue.toDouble() < mExtent.xMinimum()) mExtent.setXMinimum(longitudeValue.toDouble());
        if(longitudeValue.toBool() > mExtent.xMaximum()) mExtent.setXMaximum(longitudeValue.toDouble());
        if(latitudeValue.toDouble() < mExtent.yMinimum()) mExtent.setYMinimum(latitudeValue.toDouble());
        if(latitudeValue.toDouble() > mExtent.yMaximum()) mExtent.setYMaximum(latitudeValue.toDouble());
      }

      wkt.append(longitude).append(" ").append(latitude);
    }
  }

  wkt.append("))");
  QgsMultiLineString *pLineString = new QgsMultiLineString();
  if(!pLineString->fromWkt(wkt)) {
    pushError("Application Error (WKT LineString).");
    return;
  }

  QgsGeometry result(pLineString);
  pContainer->mFeature.setGeometry(result);
}

void QgsStanag4778JsonProvider::extractMutiPolygon(const QJsonObject &geometry, FeatureContainer *pContainer, bool first) {
  QByteArray wkt;
  auto coordinatesValue = geometry.value("coordinates");
  if(coordinatesValue.type() != QJsonValue::Array) {
    pushError("Invalid STANAG JSON message received (Coordinates).");
    return;
  }

  auto polygons = coordinatesValue.toArray();
  wkt.reserve(19 + (polygons.size() * 264));
  wkt.append("MULTIPOLYGON (((");
  bool endPolygon = false;
  for(auto polygonValue : polygons) {
    if(polygonValue.type() != QJsonValue::Array) {
      pushError("Invalid STANAG JSON message received (Polygons).");
      return;
    }

    if(endPolygon) wkt.append("), (");
    else endPolygon = true;

    auto polygon = polygonValue.toArray();
    bool addRingComma = false;
    for(auto ringsValue : polygon) {
      if(ringsValue.type() != QJsonValue::Array) {
        pushError("Invalid STANAG JSON message received (Rings).");
        return;
      }

      if(addRingComma) wkt.append("), (");
      else addRingComma = true;

      auto ring = ringsValue.toArray();
      bool addComma = false;
      for(auto pointsValue : ring) {
        if(pointsValue.type() != QJsonValue::Array) {
          pushError("Invalid STANAG JSON message received (Ring Points).");
          return;
        }

        if(addComma) wkt.append(", ");
        else addComma = true;

        auto point = pointsValue.toArray();
        auto longitudeValue = point[0];
        auto latitudeValue = point[1];
        if((longitudeValue.type() != QJsonValue::Double) || (latitudeValue.type() != QJsonValue::Double)) {
          pushError("Invalid STANAG JSON message received (Ring Point).");
          return;
        }
        auto longitude = QByteArray::number(longitudeValue.toDouble());
        auto latitude = QByteArray::number(latitudeValue.toDouble());

        if(first) {
          mExtent.set(longitude.toDouble(), latitude.toDouble(), longitude.toDouble(), latitude.toDouble());
          first = false;

        } else {
          if(longitudeValue.toDouble() < mExtent.xMinimum()) mExtent.setXMinimum(longitudeValue.toDouble());
          if(longitudeValue.toBool() > mExtent.xMaximum()) mExtent.setXMaximum(longitudeValue.toDouble());
          if(latitudeValue.toDouble() < mExtent.yMinimum()) mExtent.setYMinimum(latitudeValue.toDouble());
          if(latitudeValue.toDouble() > mExtent.yMaximum()) mExtent.setYMaximum(latitudeValue.toDouble());
        }

        wkt.append(longitude).append(" ").append(latitude);
      }
    }
  }

  wkt.append(")))");
  QgsMultiPolygon *pPolygon = new QgsMultiPolygon();
  if(!pPolygon->fromWkt(wkt)) {
    pushError("Application Error (WKT Polygon).");
    return;
  }

  QgsGeometry result(pPolygon);
  pContainer->mFeature.setGeometry(result);
}

void QgsStanag4778JsonProvider::fixFeatures(const QList<QgsStanag4778JsonProvider::FeatureContainer> &features) {

  for(auto item : features) {
    item.mFeature.setFields(mFields);
    item.mFeature.initAttributes(mFields.size());
    for(auto i = 0; i < mFields.size(); i++) {
      auto value = item.mAttributes.contains(mFields.at(i).name()) ? item.mAttributes.value(mFields.at(i).name()) : QVariant(mFields.at(i).type());
      item.mFeature.setAttribute(i, value);
    }
    mFeatures.insert(item.mFeature.id(), item.mFeature);
  }
}

QgsStanag4778JsonProvider::FeatureContainer QgsStanag4778JsonProvider::createFeature(const QString &decrypted, const QgsFeatureId index, AttributeKeyMap *pAttributes) {
  FeatureContainer container;
  auto document = QJsonDocument::fromJson(decrypted.toUtf8());
  if(document.isNull() || !document.isObject()) {
    pushError("Invalid STANAG JSON message received (Create Feature).");
    return container;
  }

  auto root = document.object();
  auto idValue = root.value("id");
  QgsFeatureId id;
  QString idString;
  bool addIdAttribute = false;
  switch(idValue.type()) {
    case QJsonValue::String:
      id = index;
      idString = idValue.toString();
      addIdAttribute = true;
      break;

    case QJsonValue::Double:
      id = idValue.toInt();
      break;

    default:
      pushError("Invalid STANAG JSON message received (Create Feature).");
      return container;
  }

  if(addIdAttribute) {
    auto size = ((idValue.toString().length() / 10) + 1) * 10;
    auto pos = mFields.indexOf("id");
    if(pos == -1) {
      QgsField idField(QStringLiteral("id"), QVariant::String, QStringLiteral("text"), size, 0, QString(), QVariant::String);
      mFields.append(idField);

    } else if(size > mFields.field(pos).length()) {
      auto field = mFields.field(pos);
      field.setLength(size);
      mFields.remove(pos);
      mFields.append(field);
    }
    pAttributes->insert(QStringLiteral("id"), QVariant(idString));
  }

  QgsFeature feature(id);
  container.mFeature = feature;
  container.mAttributes = *pAttributes;

  return container;
}

QgsStanag4778JsonProvider::AttributeKeyMap QgsStanag4778JsonProvider::addNewFields(const QString &decrypted) {

  QMap<QString, QVariant> result;

  auto document = QJsonDocument::fromJson(decrypted.toUtf8());
  if(document.isNull() || !document.isObject()) {
    pushError("Invalid STANAG JSON message received (Feature).");
    return result;
  }

  auto root = document.object();
  auto propertiesValue = root.value("properties");
  if(propertiesValue.type() != QJsonValue::Object) {
    pushError("Invalid STANAG JSON message received (Properties).");
    return result;
  }

  auto properties = propertiesValue.toObject();
  for(const auto &key : properties.keys()) {
    auto value = properties.value(key);
    int pos;
    switch(value.type()) {
      case QJsonValue::Bool:
        pos = mFields.indexOf(key);
        if( pos == -1 ) {
          QgsField field( key, QVariant::Bool, QStringLiteral("bool"), 0, 0, QString(), QVariant::Bool );
          mFields.append(field);

        } else {
          auto field = mFields.field(pos);
          switch(field.type()) {
            case QVariant::Bool:
              break;

            default:
              pushError("Invalid STANAG JSON message received (Bool).");
              return result;
          }
        }

        result.insert(key, QVariant(value.toBool()));
        break;

      case QJsonValue::Double:
        {
          auto stringRep = QString::number(value.toDouble());
          auto period = stringRep.indexOf(".");
          auto precision = period > 0 ? stringRep.trimmed().mid(period).length() : 0;
          auto variantType = precision == 0 ? QVariant::Int : QVariant::Double;
          auto variantName = precision == 0 ? QStringLiteral("integer") : QStringLiteral("double");

          pos = mFields.indexOf(key);
          if( pos == -1 ) {
            QgsField field( key, variantType, variantName, 0, precision, QString(), variantType );
            mFields.append(field);

          } else {
            auto field = mFields.field(pos);
            switch(field.type()) {
              case QVariant::Double:
              case QVariant::Int:
                if(precision > field.precision()) {
                  field.setPrecision(precision);
                  if(field.type() == QVariant::Int) {
                    field.setType(variantType);
                    field.setSubType(variantType);
                    field.setTypeName(variantName);
                    mFields.remove(pos);
                    mFields.append(field);
                  }
                }
                break;

              default:
                pushError("Invalid STANAG JSON message received (Double).");
                return result;
            }
          }

          auto field = mFields.field(key);
          auto fieldValue = field.type() == QVariant::Int ? value.toInt() : value.toDouble();
          result.insert(key, QVariant(fieldValue));
        }
        break;

      case QJsonValue::String:
         {
           auto size =  ((value.toString().length() / 100) + 1) * 100;
           pos = mFields.indexOf(key);
           if( pos == -1 ) {
             auto type = value.type() == QJsonValue::Null ? QVariant::Invalid : QVariant::String;
             QgsField field( key, QVariant::String, QStringLiteral("text"), size, 0, QString(), type );
             mFields.append(field);

           } else {
             auto field = mFields.field(pos);
             switch(field.type()) {
               case QVariant::String:
                 if(field.length() < size) {
                   field.setLength(size);
                   mFields.remove(pos);
                   mFields.append(field);
                 }
                 break;

                 default:
                   pushError("Invalid STANAG JSON message received (String).");
                   return result;
              }
           }
        }

        result.insert(key, QVariant(value.toString()));
        break;

      case QJsonValue::Object:
      case QJsonValue::Array:
      case QJsonValue::Undefined:
      case QJsonValue::Null:
     default:
        pushError("Invalid STANAG JSON message received (Property).");
        break;
    }
  }

  return result;
}

void QgsStanag4778JsonProvider::extractWktType(const QString &decrypted) {
  auto document = QJsonDocument::fromJson(decrypted.toUtf8());
  if(document.isNull() || !document.isObject()) {
    pushError("Invalid STANAG JSON message received (WKT).");
    return;
  }

  auto root = document.object();
  auto geometryValue = root.value("geometry");
  if(geometryValue.type() != QJsonValue::Object) {
    pushError("Invalid STANAG JSON message received (Geometry).");
    return;
  }

  auto geometry = geometryValue.toObject();
  auto type = geometry.value("type");
  if(type.type() != QJsonValue::String) {
    pushError("Invalid STANAG JSON message received (Geometry Type).");
    return;
  }

  auto geomString = type.toString().toUpper();
  if(geomString.endsWith("ZM")) geomString = geomString.left(geomString.length() - 2) + " ZM";
  else if(geomString.endsWith("Z")) geomString = geomString.left(geomString.length() - 1) + " Z";
  else if(geomString.endsWith("M")) geomString = geomString.left(geomString.length() - 1) + " M";
  mWkbType = QgsWkbTypes::parseType(geomString);
}

void QgsStanag4778JsonProvider::initDataTypes() {

    setNativeTypes( QList< NativeType >()
                  << QgsVectorDataProvider::NativeType( tr( "Whole number (integer)" ), QStringLiteral( "integer" ), QVariant::Int, 0, 10 )
                  // Decimal number from OGR/Shapefile/dbf may come with length up to 32 and
                  // precision up to length-2 = 30 (default, if width is not specified in dbf is length = 24 precision = 15)
                  // We know that double (QVariant::Double) has only 15-16 significant numbers,
                  // but setting that correct limits would disable the use of memory provider with
                  // data from Shapefiles. In any case, the data are handled as doubles.
                  // So the limits set here are not correct but enable use of data from Shapefiles.
                  << QgsVectorDataProvider::NativeType( tr( "Decimal number (real)" ), QStringLiteral( "double" ), QVariant::Double, 0, 32, 0, 30 )

                  // string types
                  << QgsVectorDataProvider::NativeType( tr( "Text, unlimited length (text)" ), QStringLiteral( "text" ), QVariant::String, -1, -1, -1, -1 )

                  // boolean
                  << QgsVectorDataProvider::NativeType( tr( "Boolean" ), QStringLiteral( "bool" ), QVariant::Bool )
                );
}

/**
 * Returns the coordinate system for the data source.
 * If the provider isn't capable of returning its projection then an invalid
 * QgsCoordinateReferenceSystem will be returned.
 */
QgsCoordinateReferenceSystem QgsStanag4778JsonProvider::crs() const {

  return mCrs;
}

/**
 * Returns the extent of the layer
 * \returns QgsRectangle containing the extent of the layer
 */
QgsRectangle QgsStanag4778JsonProvider::extent() const {

  return mExtent;
}

/**
 * Returns TRUE if this is a valid layer. It is up to individual providers
 * to determine what constitutes a valid layer.
 */
bool QgsStanag4778JsonProvider::isValid() const {

  return !hasErrors();
}

/**
 * Returns a provider name
 *
 * Essentially just returns the provider key.  Should be used to build file
 * dialogs so that providers can be shown with their supported types. Thus
 * if more than one provider supports a given format, the user is able to
 * select a specific provider to open that file.
 *
 * \note
 *
 * Instead of being pure virtual, might be better to generalize this
 * behavior and presume that none of the sub-classes are going to do
 * anything strange with regards to their name or description?
 */
QString QgsStanag4778JsonProvider::name() const {

  return TEXT_PROVIDER_KEY;
}

/**
 * Returns description
 *
 * Returns a terse string describing what the provider is.
 *
 * \note
 *
 * Instead of being pure virtual, might be better to generalize this
 * behavior and presume that none of the sub-classes are going to do
 * anything strange with regards to their name or description?
 */
QString QgsStanag4778JsonProvider::description() const {

  return TEXT_PROVIDER_DESCRIPTION;
}

/**
 * Returns feature source object that can be used for querying provider's data. The returned feature source
 * is independent from provider - any changes to provider's state (e.g. change of subset string) will not be
 * reflected in the feature source, therefore it can be safely used for processing in background without
 * having to care about possible changes within provider that may happen concurrently. Also, even in the case
 * of provider being deleted, any feature source obtained from the provider will be kept alive and working
 * (they are independent and owned by the caller).
 *
 * Sometimes there are cases when some data needs to be shared between vector data provider and its feature source.
 * In such cases, the implementation must ensure that the data is not susceptible to run condition. For example,
 * if it is possible that both feature source and provider may need reading/writing to some shared data at the
 * same time, some synchronization mechanisms must be used (e.g. mutexes) to prevent data corruption.
 *
 * \returns new instance of QgsAbstractFeatureSource (caller is responsible for deleting it)
 */
QgsAbstractFeatureSource *QgsStanag4778JsonProvider::featureSource() const {

  return new QgsStanag4778JsonFeatureSource(this);
}

/**
 * Returns the permanent storage type for this layer as a friendly name.
 */
QString QgsStanag4778JsonProvider::storageType() const {

  return QStringLiteral("STANAG 4778 JSON Features");
};

/**
 * Query the provider for features specified in request.
 * \param request feature request describing parameters of features to return
 * \returns iterator for matching features from provider
 */
QgsFeatureIterator QgsStanag4778JsonProvider::getFeatures( const QgsFeatureRequest &request ) const {

  return QgsFeatureIterator(new QgsStanag4778JsonFeatureIterator(new QgsStanag4778JsonFeatureSource(this), true, request));
};

/**
 * Returns the geometry type which is returned by this layer
 */
QgsWkbTypes::Type QgsStanag4778JsonProvider::wkbType() const {

  return mWkbType;
};

/**
 * Number of features in the layer
 * \returns long containing number of features
 */
long QgsStanag4778JsonProvider::featureCount() const {

    return mFeatureCount;
};

/**
 * Returns the fields associated with this data provider.
 */
QgsFields QgsStanag4778JsonProvider::fields() const {

  return mFields;
};

//------------------------------ Metadata --------------------

QgsStanag4778JsonProviderMetadata::QgsStanag4778JsonProviderMetadata()
: QgsProviderMetadata(TEXT_PROVIDER_KEY, TEXT_PROVIDER_DESCRIPTION) {

}

/**
 * Class factory to return a pointer to a newly created
 * QgsOgrProvider object
 */
QgsStanag4778JsonProvider *QgsStanag4778JsonProviderMetadata::createProvider( const QString &uri, const QgsDataProvider::ProviderOptions &options )
{
  auto revisedOptions = (StanagProviderOptions *)&options;
  return new QgsStanag4778JsonProvider( uri, *revisedOptions );
}

QGISEXTERN QgsProviderMetadata *providerMetadataFactory()
{
  return new QgsStanag4778JsonProviderMetadata();
}

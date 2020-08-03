/***************************************************************************
            qgsstanag4778jsonprovider.h Data provider for STANAG 4778 JSON
begin                : July 25, 2020
copyright            : (C) 2020 by Maxar Technologies, Inc.
email                : michael dot leedahl at maxar.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef QGSSTANAG4778JSONPROVIDER_H
#define QGSSTANAG4778JSONPROVIDER_H

#define SIP_NO_FILE

#include "qgsvectordataprovider.h"
#include "qgscoordinatereferencesystem.h"
#include "qgsfields.h"
#include "qgsstanag4778provideroptions.h"
#include "qgsprovidermetadata.h"
#include "qgsspatialindex.h"

typedef QMap<QgsFeatureId, QgsFeature> QgsFeatureMap;

class QgsField;
class QgsVectorLayerExporter;
class QgsProviderMetadata;
class QgsStanag4778JsonFeatureIterator;

/**
  \class QgsStanag4778JsonProvider
  \brief Data provider for Stanag4778Json datasources
  */
class QgsStanag4778JsonProvider final: public QgsVectorDataProvider
{
    Q_OBJECT

  public:
    /**
     * Constructor of the vector provider
     * \param uri uniform resource locator (URI) for a dataset
     * \param options generic data provider options
     */
    explicit QgsStanag4778JsonProvider( QString const &message,
                             const StanagProviderOptions &providerOptions );

    ~QgsStanag4778JsonProvider() override {}

    /**
     * Returns the coordinate system for the data source.
     * If the provider isn't capable of returning its projection then an invalid
     * QgsCoordinateReferenceSystem will be returned.
     */
    QgsCoordinateReferenceSystem crs() const override;

    /**
     * Returns the extent of the layer
     * \returns QgsRectangle containing the extent of the layer
     */
    QgsRectangle extent() const override;

    /**
     * Returns TRUE if this is a valid layer. It is up to individual providers
     * to determine what constitutes a valid layer.
     */
    bool isValid() const override;

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
    QString name() const override;


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
    QString description() const override;

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
    QgsAbstractFeatureSource *featureSource() const override;

    /**
     * Returns the permanent storage type for this layer as a friendly name.
     */
    QString storageType() const override;

    /**
     * Query the provider for features specified in request.
     * \param request feature request describing parameters of features to return
     * \returns iterator for matching features from provider
     */
    QgsFeatureIterator getFeatures(const QgsFeatureRequest &request = QgsFeatureRequest()) const override;

    /**
     * Returns the geometry type which is returned by this layer
     */
    QgsWkbTypes::Type wkbType() const override;

    /**
     * Number of features in the layer
     * \returns long containing number of features
     */
    long featureCount() const override;

    /**
     * Returns the fields associated with this data provider.
     */
    QgsFields fields() const override;

  private:
    // Coordinate reference system
    QgsCoordinateReferenceSystem mCrs;

    // fields
    QgsFields mFields;
    QgsWkbTypes::Type mWkbType;
    mutable QgsRectangle mExtent;

    // features
    QgsFeatureMap mFeatures;
    QgsFeatureId mNextFeatureId;
    int mFeatureCount = 0;

    // indexing
    QgsSpatialIndex *mSpatialIndex = nullptr;

    QString mSubsetString;

    friend class QgsStanag4778JsonFeatureSource;

    typedef QMap<QString, QVariant> AttributeKeyMap;
    struct FeatureContainer {
      QgsFeature mFeature;
      QgsStanag4778JsonProvider::AttributeKeyMap mAttributes;
    };

    void initDataTypes();
    void parseFeatures(const QString &message, const QgsAuthorizationSettings &auth);
    void parseGeometry(const QString &decrypted, FeatureContainer *pContainer, bool first);
    void extractMutiLineString(const QJsonObject &geometry, FeatureContainer *pContainer, bool first);
    void extractPoint(const QJsonObject &geometry, FeatureContainer *pContainer, bool first);
    void extractMutiPolygon(const QJsonObject &geometry, FeatureContainer *pContainer, bool first);
    AttributeKeyMap addNewFields(const QString &decrypted);
    void extractWktType(const QString &decrypted);
    FeatureContainer createFeature(const QString &decrypted, const QgsFeatureId id, AttributeKeyMap *pAttributes);
    void fixFeatures(const QList<QgsStanag4778JsonProvider::FeatureContainer> &features);
};

/**
 * Entry point for registration of the S4778J data provider
  */
class QgsStanag4778JsonProviderMetadata final: public QgsProviderMetadata
{
  public:

    QgsStanag4778JsonProviderMetadata();

  public:
    QgsStanag4778JsonProvider *createProvider( const QString &data, const QgsDataProvider::ProviderOptions &options ) override;

};

#endif // QGSSTANAG4778JSONPROVIDER_H

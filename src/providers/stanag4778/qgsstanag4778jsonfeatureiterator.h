/***************************************************************************
    qgsstanag4778jsonfeatureiterator.h
    ---------------------
    begin                : Jul 2020
    copyright            : (C) 2012 by Maxar Technologies
    email                : michael dot leedahl at maxar dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
#ifndef QGSSTANAG4778JSONFEATUREITERATOR_H
#define QGSSTANAG4778JSONFEATUREITERATOR_H

#define SIP_NO_FILE

#include "qgsfeatureiterator.h"
#include "qgsexpressioncontext.h"
#include "qgsstanag4778jsonprovider.h"
#include "qgsfields.h"
#include "qgsgeometry.h"

class QgsMemoryProvider;

typedef QMap<QgsFeatureId, QgsFeature> QgsFeatureMap;

class QgsSpatialIndex;


class QgsStanag4778JsonFeatureSource final: public QgsAbstractFeatureSource
{
  public:
    explicit QgsStanag4778JsonFeatureSource(const QgsStanag4778JsonProvider *p);

    QgsFeatureIterator getFeatures(const QgsFeatureRequest &request) override;

  private:
    QgsFields mFields;
    QgsFeatureMap mFeatures;
    std::unique_ptr< QgsSpatialIndex > mSpatialIndex;
    QString mSubsetString;
    QgsExpressionContext mExpressionContext;
    QgsCoordinateReferenceSystem mCrs;

    friend class QgsStanag4778JsonFeatureIterator;
};


class QgsStanag4778JsonFeatureIterator final: public QgsAbstractFeatureIteratorFromSource<QgsStanag4778JsonFeatureSource>
{
  public:
    QgsStanag4778JsonFeatureIterator(QgsStanag4778JsonFeatureSource *source, bool ownSource, const QgsFeatureRequest &request);

    ~QgsStanag4778JsonFeatureIterator() override;

    bool rewind() override;
    bool close() override;

  protected:

    bool fetchFeature( QgsFeature &feature ) override;

  private:
    bool nextFeatureUsingList(QgsFeature &feature);
    bool nextFeatureTraverseAll(QgsFeature &feature);

    QgsGeometry mSelectRectGeom;
    std::unique_ptr< QgsGeometryEngine > mSelectRectEngine;
    QgsRectangle mFilterRect;
    QgsFeatureMap::const_iterator mSelectIterator;
    bool mUsingFeatureIdList = false;
    QList<QgsFeatureId> mFeatureIdList;
    QList<QgsFeatureId>::const_iterator mFeatureIdListIterator;
    std::unique_ptr< QgsExpression > mSubsetExpression;
    QgsCoordinateTransform mTransform;
};

#endif // QGSSTANAG4778JSONFEATUREITERATOR_H

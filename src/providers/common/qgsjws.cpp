/***************************************************************************
    ogsjws.cpp
    ---------------------
    begin                : July 2020
    copyright            : (C) 2020 by Maxar Technologies, Inc.
    email                : michael dot leedahl at maxar dot com

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

#include "qgsjws.h"
#include "qgis.h"

#include <QUrl>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QByteArray>
#include <QEventLoop>
#include <QWaitCondition>
#include <QMutex>

#include <memory>

/**
 * Constructs the utility class and loads the PEM file containing the public key used to sign the message.
 * @param pemUrl is the URL for the PEM file.
 * @param signedText is the JWS message.
 */
QgsJws::QgsJws(const QgsAuthorizationSettings &auth, const QString &pemUrl, const QString &signedText) :
QgsBaseNetworkRequest( QgsAuthorizationSettings( auth.mUserName, auth.mPassword, auth.mAuthCfg ), tr( "OAPIF" ) ),
mSignedText(signedText) {

  mInit = QCA::Initializer();
  connect(this, &QgsBaseNetworkRequest::downloadFinished, this, &QgsJws::readPem, Qt::DirectConnection);
  sendGET(QUrl(pemUrl), "text/plain,application/pem-certificate-chain", true, true );
  mParts = mSignedText.split(".");
}

/**
 * Validates the signature on the message to ensure that the message has not been tampered with in transit.
 * @return a boolean to signal if the message is valid and unmodified.
 */
bool QgsJws::validSignature() const {
  bool error = mError;

  if(!error) {
    QCA::PublicKey publicKey = mPem;

    if (mParts.count() != 3) error = true;
    else {
      QByteArray protectedParts = QString("%1.%2").arg(mParts[0]).arg(mParts[1]).toUtf8();
      if (publicKey.canVerify()) {
        publicKey.startVerify(QCA::EMSA3_SHA256);
        publicKey.update(protectedParts); // might be called multiple times
        error = !publicKey.validSignature(QByteArray::fromBase64(mParts[2].toUtf8(),
                                                                 QByteArray::Base64UrlEncoding |
                                                                 QByteArray::OmitTrailingEquals));
      } else error = true;
    }
  }

  return !error;
}

/**
 * Retrieve the header JSON document from the JWS.
 * @return the header JSON document.
 */
QString QgsJws::header() const {

  return QByteArray::fromBase64(mParts[0].toUtf8(),
                                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

/**
 * Retrieve the message JSON document from the JWS.
 * @return the message JSON document.
 */
QString QgsJws::message() const {

  return QByteArray::fromBase64(mParts[1].toUtf8(),
                                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

/**
 * Format the reason for the error.  Method is a pure virtual method in QgsBaseNetworkRequet.
 */
QString QgsJws::errorMessageWithReason( const QString &reason )
{
  return tr( "Download of pem file failed: %1" ).arg( reason );
}

/**
 * Reads the PEM file from the current network connection.
 */
void QgsJws::readPem() {

  if ( mErrorCode == QgsBaseNetworkRequest::ErrorCode::NoError )
  {
      mPem = QCA::PublicKey::fromPEM(mResponse);
      mError = false;

  } else mError = true;

  emit finished();
}
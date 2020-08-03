/***************************************************************************
    oqsjwe.h
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

#ifndef QGSJWS_H
#define QGSJWS_H

#include <QString>
#include <QObject>
#include <QNetworkReply>
#include <QThread>
#include <QtCrypto>
#include "../wfs/qgsauthorizationsettings.h"
#include "../wfs/qgsbasenetworkrequest.h"

/**
 * Jws is a utility that implements the JOSE JWS standard for validating and extracting content from Signed JSON
 * text.  This implementation works for Compact JWS Signed with the RS256 Algorithm. A Compact JWS text is divided
 * into three parts that are BASE64URL encoded and separated by a single period.  The first part contains the
 * protected header which describes the algorithm and key to use to calculate out a signature.  The second part
 * contains the protected payload.  The payload could be any byte string but this utility assumes that the payload
 * is a UTF-8 string.  The third part is the signature of the associated BASE64URL encoded header and payload separated
 * by a period.
 */
class QgsJws : public QgsBaseNetworkRequest {

  Q_OBJECT

public:
  /**
   * Constructs the utility class and loads the PEM file containing the public key used to sign the message.
   * @param pemUrl is the URL for the PEM file.
   * @param signedText is the JWS message.
   */
  explicit QgsJws( const QgsAuthorizationSettings &auth, const QString &pemUrl, const QString &signedText );

  /**
   * Validates the signature on the message to ensure that the message has not been tampered with in transit.
   * @return a boolean to signal if the message is valid and unmodified.
   */
  bool validSignature() const;

  /**
   * Retrieve the header JSON document from the JWS.
   * @return the header JSON document.
   */
  QString header() const;

  /**
   * Retrieve the message JSON document from the JWS.
   * @return the message JSON document.
   */
  QString message() const;

protected:
  /**
   * Format the reason for the error.  Method is a pure virtual method in QgsBaseNetworkRequet.
   */
  QString errorMessageWithReason( const QString &reason ) override;

private slots:
  /**
   * Reads the PEM file from the current network connection.
   */
  void readPem();

signals:
  void finished();

private:
  QCA::PublicKey mPem;    // The contents of the downloaded PEM file as a public key.
  QString mSignedText;    // The JWS message containing the signed header and payload with the signature value.
  QNetworkReply *mReply;  // The reply from the network request.
  bool mError;            // Indicates if an error was detected when downloading the PEM file.
  QCA::Initializer mInit; // The initializer for the Cryptographic libraries.
  QStringList mParts;     // The list of parts derived from the Signed Text of the JWE.
};

#endif //QGSJWS_H

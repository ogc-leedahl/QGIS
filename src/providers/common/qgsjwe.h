/***************************************************************************
    oqsjws.h
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

#ifndef QGSJWE_H
#define QGSJWE_H

#include <QString>
#include <QObject>
#include <QNetworkReply>
#include <QThread>
#include <QtCrypto>
#include <QByteArray>
#include "../wfs/qgsauthorizationsettings.h"
#include "../wfs/qgsbasenetworkrequest.h"

/**
 * Jwe is a utility that implements the JOSE JWE standard for representing encrypted JSON text.  This
 * implementation works with a variety of semetric encryption algorithms. The JWE text is divided into two
 * parts that are BASE64URL encoded and separated by a two period.  The first part contains the header which
 * describes the algorithm and key to use to decrypt the message.  The second part contains the encrypted payload.
 * The payload could be any byte string but this utility assumes that the payload is a UTF-8 string.
 */
class QgsJwe : public QgsBaseNetworkRequest {

  Q_OBJECT

public:
  /**
   * Constructs the utility class and loads the key that is used to decrypt the message.
   * @param auth is the authorization structure containing information about how to authenticate with the key server.
   * @param keyServerUrl is the URL for the key server.
   * @param encryptedText is the JWE message.
   */
  explicit QgsJwe( const QgsAuthorizationSettings &auth, const QString &encryptedText );

  /**
   * Retrieve the header JSON document from the JWE.
   * @return the header JSON document.
   */
  QString header() const;

  /**
   * Retrieve the decrypted message JSON document from the JWE.
   * @return the decrypted message JSON document.
   */
  QString message();

  /**
   * Sets a new encrypted text to process.
   * @param encryptedText is the message to decrypt.
   */
  void setEncryptedText(const QString &encryptedText);

protected:
  /**
   * Format the reason for the error.  Method is a pure virtual method in QgsBaseNetworkRequet.
   */
  QString errorMessageWithReason( const QString &reason ) override;

private slots:
  /**
   * Reads the key from the current network connection.
   */
  void readKey();

signals:
  void finished();

private:
  typedef QMap<QString, QByteArray> KeyMap;

  QString mAlgorithm;     // The encryption algorithm to apply.
  QString mCurrentKeyId;  // The identifier for the key to use for the current encrypted text.
  KeyMap mKeyMap;         // The map of key to use for decrypting payloads.
  QByteArray mIv;         // The initialization vector for the encreption algorithm.
  QNetworkReply *mReply;  // The reply from the network request.
  QCA::Initializer mInit; // The initializer for the Cryptographic libraries.
  QStringList mParts;     // The list of parts derived from the encrypted text in the JWE.
};

#endif //QGSJWE_H
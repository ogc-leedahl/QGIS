/***************************************************************************
    ogsjwe.cpp
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

#include "qgsjwe.h"
#include "qgis.h"

#include <QUrl>
#include <QWaitCondition>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QDataStream>

#include <memory>

/**
 * Constructs the utility class and loads the key that is used to decrypt the message.
 * @param auth is the authorization structure containing information about how to authenticate with the key server.
 * @param keyServerUrl is the URL for the key server.
 * @param encryptedText is the JWE message.
 */
QgsJwe::QgsJwe(const QgsAuthorizationSettings &auth, const QString &encryptedText) :
QgsBaseNetworkRequest( auth, tr( "OAPIF" ) ) {

  mInit = QCA::Initializer();
  connect(this, &QgsBaseNetworkRequest::downloadFinished, this, &QgsJwe::readKey, Qt::DirectConnection);
  setEncryptedText(encryptedText);
}

/**
 * Sets a new encrypted text to process.
 * @param encryptedText is the message to decrypt.
 */
void QgsJwe::setEncryptedText(const QString &encryptedText) {
  mParts = encryptedText.split(".");
  auto buffer = QByteArray::fromBase64(mParts[0].toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
  auto document = QJsonDocument::fromJson(buffer);
  if(document.isNull() || !document.isObject()) {
    mErrorCode = ErrorCode::ApplicationLevelError;
    mErrorMessage = "Application Error (Message).";
    return;
  }

  auto root = document.object();
  auto keyId = root.value("kid");
  if(keyId.type() != QJsonValue::String) {
    mErrorCode = ErrorCode::ApplicationLevelError;
    mErrorMessage = "Application Error (Key Id).";
    return;
  }

  mCurrentKeyId = keyId.toString();
  if(!mKeyMap.contains(mCurrentKeyId)) {
    QUrl url(QStringLiteral("%1/keys/%2?key_verifier=%3").arg(mAuth.mKmsUrl).arg(mCurrentKeyId).arg(mAuth.mKeyChallenge));
    sendGET(url, "application/json", true, true );
  }
}

/**
 * Retrieve the header JSON document from the JWE.
 * @return the header JSON document.
 */
QString QgsJwe::header() const {

  return QByteArray::fromBase64(mParts[0].toUtf8(),
                                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

/**
 * Retrieve the decrypted message JSON document from the JWE.
 * @return the decrypted message JSON document.
 */
QString QgsJwe::message() {

  QString plainText;
  QCA::SymmetricKey key(mKeyMap[mCurrentKeyId].right(mKeyMap[mCurrentKeyId].size()/2));
  QCA::InitializationVector iv(QByteArray::fromBase64(mParts[2].toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
  auto payload = QByteArray::fromBase64(mParts[3].toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

  if(mAlgorithm == "A192CBC-HS384") {
    if(!verifyHMAC(QLatin1Literal("hmac(sha384)"))) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption HMAC 384).";
      return QString();
    }

    QCA::Cipher cipher("aes192",  QCA::Cipher::CBC, QCA::Cipher::Padding::PKCS7, QCA::Direction::Decode, key, iv);
    auto plain = cipher.process(payload);
    if(!cipher.ok()) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption).";
      return QString();
    }
    plainText = plain.toByteArray();

  } else if(mAlgorithm == "A256CBC-HS512") {
    if(!verifyHMAC(QLatin1Literal("hmac(sha512)"))) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption HMAC 512).";
      return QString();
    }

    QCA::Cipher cipher("aes256",  QCA::Cipher::CBC, QCA::Cipher::Padding::PKCS7, QCA::Direction::Decode, key, iv);
    auto plain = cipher.process(payload);
    if(!cipher.ok()) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption).";
      return QString();
    }
    plainText = plain.toByteArray();

  } else if(mAlgorithm == "A128CBC-HS256") {
    if(!verifyHMAC(QLatin1Literal("hmac(sha256)"))) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption HMAC 256).";
      return QString();
    }

    QCA::Cipher cipher(QStringLiteral("aes128"),  QCA::Cipher::CBC, QCA::Cipher::Padding::PKCS7, QCA::Direction::Decode, key, iv);
    auto plain = cipher.process(payload);
    if(!cipher.ok()) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Decryption).";
      return QString();
    }
    plainText = plain.toByteArray();
  }

  return plainText;
}

/**
 * Verifies the HMAC value.
 * return: true if the HMAC is valid.
 */
bool QgsJwe::verifyHMAC(const QString &algorithm) {

    auto hmacKey = QCA::SymmetricKey(mKeyMap[mCurrentKeyId].left(mKeyMap[mCurrentKeyId].size()/2));

    auto aad = mParts[0].toUtf8();
    auto iv = QByteArray::fromBase64(mParts[2].toUtf8(), QByteArray::Base64UrlEncoding);
    auto cipherText = QByteArray::fromBase64(mParts[3].toUtf8(), QByteArray::Base64UrlEncoding);
    auto authTag = QByteArray::fromBase64(mParts[4].toUtf8(), QByteArray::Base64UrlEncoding);

    QByteArray al;
    al.reserve(8);
    QDataStream stream(&al, QIODevice::WriteOnly);
    quint64 aadSize = aad.size() * 8;
    stream << aadSize;

    QByteArray message;
    message.reserve(aad.size() + iv.size() + cipherText.size() + al.size());
    message.append(aad).append(iv).append(cipherText).append(al);

    auto hmacAlgorithm = QCA::MessageAuthenticationCode(algorithm, hmacKey, QString());
    auto hmac = hmacAlgorithm.process(message).toByteArray();

    if(hmac.left(hmac.size()/2) != authTag) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (HMAC).";
      return false;
    }

    qDebug() << "QgsJwe::verifyHMAC: HMAC on key (" + mCurrentKeyId + ") is valid.";

    return true;
}

/**
 * Format the reason for the error.  Method is a pure virtual method in QgsBaseNetworkRequet.
 */
QString QgsJwe::errorMessageWithReason( const QString &reason )
{
  return tr( "Download of key failed: %1" ).arg( reason );
}

/**
 * Reads the key from the current network connection.
 */
void QgsJwe::readKey() {

  if ( mErrorCode == ErrorCode::NoError )
  {
    auto document = QJsonDocument::fromJson(mResponse);
    if(document.isNull() || !document.isObject()) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Message).";
      return;
    }

    auto root = document.object();
    auto algorithm = root.value("alg");
    if(algorithm.type() != QJsonValue::String) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Agorithm).";
      return;
    }
    mAlgorithm = algorithm.toString();

    auto keyValue = root.value("k");
    if(keyValue.type() != QJsonValue::String) {
      mErrorCode = ErrorCode::ApplicationLevelError;
      mErrorMessage = "Application Error (Key).";
      return;
    }
    auto key = QByteArray::fromBase64(keyValue.toString().toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    mKeyMap.insert(mCurrentKeyId, key);
  }

  emit finished();
}
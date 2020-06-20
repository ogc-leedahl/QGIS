/***************************************************************************
    begin                : July 13, 2016
    copyright            : (C) 2016 by Monsanto Company, USA
    author               : Larry Shaffer, Boundless Spatial
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsauthoauth2edit.h"
#include "ui_qgsauthoauth2edit.h"

#include <QDir>
#include <QFileDialog>
#include <QDesktopServices>
#include <QSslCertificate>
#include <QBitArray>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

#include "qgsapplication.h"
#include "qgsauthguiutils.h"
#include "qgsauthmanager.h"
#include "qgsauthconfigedit.h"
#include "qgsmessagelog.h"
#include "qgsnetworkaccessmanager.h"
#include "qjsonwrapper/Json.h"
#include "qgis.h"

QgsAuthOAuth2Edit::QgsAuthOAuth2Edit( QWidget *parent )
  : QgsAuthMethodEdit( parent )
  , mDefinedConfigsCache( QgsStringMap() )
{
  setupUi( this );

  initGui();

  initConfigObjs();

  populateGrantFlows();
  updateGrantFlow( static_cast<int>( QgsAuthOAuth2Config::AuthCode ) ); // first index: Authorization Code

  populateAccessMethods();

  populateRegGrantType();

  populateRegTokenAuthMethods();
  
  populateRegKeySet();

  queryTableSelectionChanged();

  loadDefinedConfigs();

  setupConnections();

  loadFromOAuthConfig( mOAuthConfigCustom.get() );
  updatePredefinedLocationsTooltip();

  pteDefinedDesc->setOpenLinks( false );
  connect( pteDefinedDesc, &QTextBrowser::anchorClicked, this, [ = ]( const QUrl & url )
  {
    QDesktopServices::openUrl( url );
  } );
}


void QgsAuthOAuth2Edit::initGui()
{
  mParentName = parentNameField();

  frameNotify->setVisible( false );

  // TODO: add messagebar to notify frame?

  tabConfigs->setCurrentIndex( customTab() );

  btnExport->setEnabled( false );

  chkbxTokenPersist->setChecked( false );

  grpbxAdvanced->setCollapsed( true );
  grpbxAdvanced->setFlat( false );

  btnTokenClear = new QToolButton( this );
  btnTokenClear->setObjectName( QStringLiteral( "btnTokenClear" ) );
  btnTokenClear->setMaximumHeight( 20 );
  btnTokenClear->setText( tr( "Tokens" ) );
  btnTokenClear->setToolTip( tr( "Remove cached tokens" ) );
  btnTokenClear->setIcon( QIcon( QStringLiteral( ":/oauth2method/oauth2_resources/close.svg" ) ) );
  btnTokenClear->setIconSize( QSize( 12, 12 ) );
  btnTokenClear->setToolButtonStyle( Qt::ToolButtonTextBesideIcon );
  btnTokenClear->setEnabled( hasTokenCacheFile() );

  connect( btnTokenClear, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::removeTokenCacheFile );
  tabConfigs->setCornerWidget( btnTokenClear, Qt::TopRightCorner );
}

QWidget *QgsAuthOAuth2Edit::parentWidget() const
{
  if ( !window() )
  {
    return nullptr;
  }

  const QMetaObject *metaObject = window()->metaObject();
  QString parentclass = metaObject->className();
  //QgsDebugMsg( QStringLiteral( "parent class: %1" ).arg( parentclass ) );
  if ( parentclass != QStringLiteral( "QgsAuthConfigEdit" ) )
  {
    QgsDebugMsg( QStringLiteral( "Parent widget not QgsAuthConfigEdit instance" ) );
    return nullptr;
  }

  return window();
}

QLineEdit *QgsAuthOAuth2Edit::parentNameField() const
{
  return parentWidget() ? parentWidget()->findChild<QLineEdit *>( QStringLiteral( "leName" ) ) : nullptr;
}

QString QgsAuthOAuth2Edit::parentConfigId() const
{
  if ( !parentWidget() )
  {
    return QString();
  }

  QgsAuthConfigEdit *cie = qobject_cast<QgsAuthConfigEdit *>( parentWidget() );
  if ( !cie )
  {
    QgsDebugMsg( QStringLiteral( "Could not cast to QgsAuthConfigEdit" ) );
    return QString();
  }

  if ( cie->configId().isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "QgsAuthConfigEdit->configId() is empty" ) );
  }

  return cie->configId();
}


void QgsAuthOAuth2Edit::setupConnections()
{
  // Action and interaction connections
  connect( tabConfigs, &QTabWidget::currentChanged, this, &QgsAuthOAuth2Edit::tabIndexChanged );

  connect( btnExport, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::exportOAuthConfig );
  connect( btnImport, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::importOAuthConfig );

  connect( tblwdgQueryPairs, &QTableWidget::itemSelectionChanged, this, &QgsAuthOAuth2Edit::queryTableSelectionChanged );

  connect( btnAddQueryPair, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::addQueryPair );
  connect( btnRemoveQueryPair, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::removeQueryPair );

  connect( lstwdgDefinedConfigs, &QListWidget::currentItemChanged, this, &QgsAuthOAuth2Edit::currentDefinedItemChanged );

  connect( btnGetDefinedDirPath, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::getDefinedCustomDir );
  connect( leDefinedDirPath, &QLineEdit::textChanged, this, &QgsAuthOAuth2Edit::definedCustomDirChanged );

  connect( btnSoftStatementDir, &QToolButton::clicked, this, &QgsAuthOAuth2Edit::getSoftStatementDir );
  connect( leSoftwareStatementJwtPath, &QLineEdit::textChanged, this, &QgsAuthOAuth2Edit::softwareStatementJwtPathChanged );
  connect( leSoftwareStatementConfigUrl, &QLineEdit::textChanged, this, [ = ]( const QString & txt )
  {
    btnRegister->setEnabled( ! leSoftwareStatementJwtPath->text().isEmpty()
                             && ( QUrl( txt ).isValid() || ! mRegistrationEndpoint.isEmpty() ) );
  } );
  connect( btnRegister, &QPushButton::clicked, this, &QgsAuthOAuth2Edit::getSoftwareStatementConfig );

  // Custom config editing connections
  connect( cmbbxGrantFlow, static_cast<void ( QComboBox::* )( int )>( &QComboBox::currentIndexChanged ),
           this, &QgsAuthOAuth2Edit::updateGrantFlow ); // also updates GUI
  connect( pteDescription, &QPlainTextEdit::textChanged, this, &QgsAuthOAuth2Edit::descriptionChanged );
  connect( leRequestUrl, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRequestUrl );
  connect( leTokenUrl, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setTokenUrl );
  connect( leRefreshTokenUrl, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRefreshTokenUrl );
  connect( leRedirectUrl, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRedirectUrl );
  connect( spnbxRedirectPort, static_cast<void ( QSpinBox::* )( int )>( &QSpinBox::valueChanged ),
           mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRedirectPort );
  connect( leClientId, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setClientId );
  connect( leClientSecret, &QgsPasswordLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setClientSecret );
  connect( leUsername, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setUsername );
  connect( lePassword, &QgsPasswordLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setPassword );
  connect( leScope, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setScope );
  connect( leApiKey, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setApiKey );
  connect( chkbxTokenPersist, &QCheckBox::toggled, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setPersistToken );
  connect( cmbbxAccessMethod, static_cast<void ( QComboBox::* )( int )>( &QComboBox::currentIndexChanged ),
           this, &QgsAuthOAuth2Edit::updateConfigAccessMethod );
  connect( spnbxRequestTimeout, static_cast<void ( QSpinBox::* )( int )>( &QSpinBox::valueChanged ),
           mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRequestTimeout );

  connect( mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::validityChanged, this, &QgsAuthOAuth2Edit::configValidityChanged );

  connect( leRegAuthUrl, &QLineEdit::textChanged, this, &QgsAuthOAuth2Edit::setRegAuthUrl );
  connect( leRegAccessToken, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRegAccessToken );
  connect( leRegRedirectUrl, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRegRedirectUrl );
  connect( spnbxRegRedirectPort, static_cast<void ( QSpinBox::* )( int )>( &QSpinBox::valueChanged ),
           mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRegRedirectPort );
  connect( cmbbxRegTokenAuth, static_cast<void ( QComboBox::* )( int )>( &QComboBox::currentIndexChanged ),
          this, &QgsAuthOAuth2Edit::updateConfigRegTokenAuthMethod );
  connect( cmbbxRegGrantType, static_cast<void ( QComboBox::* )( int )>( &QComboBox::currentIndexChanged ),
          this, &QgsAuthOAuth2Edit::updateConfigRegGrantType );
  connect( leRegClientName, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRegClientName );
  connect( leRegScopes, &QLineEdit::textChanged, mOAuthConfigCustom.get(), &QgsAuthOAuth2Config::setRegScopes );
  connect( teRegContactInfo, &QPlainTextEdit::textChanged, this, &QgsAuthOAuth2Edit::regContactInfoChanged );
  connect( cmbbxRegKeySet, static_cast<void ( QComboBox::* )( int )>( &QComboBox::currentIndexChanged ),
          this, &QgsAuthOAuth2Edit::updateConfigRegKeySet );
  connect( btnRegRegister, &QPushButton::clicked, this, &QgsAuthOAuth2Edit::getClientRegistration );

  if ( mParentName )
  {
    connect( mParentName, &QLineEdit::textChanged, this, &QgsAuthOAuth2Edit::configValidityChanged );
  }
}


void QgsAuthOAuth2Edit::configValidityChanged()
{
  validateConfig();
  bool parentname = mParentName && !mParentName->text().isEmpty();
  btnExport->setEnabled( mValid && parentname );
}

bool QgsAuthOAuth2Edit::validateConfig()
{
  bool curvalid = ( onCustomTab() ? mOAuthConfigCustom->isValid() : !mDefinedId.isEmpty() );
  if ( mValid != curvalid )
  {
    mValid = curvalid;
    emit validityChanged( curvalid );
  }
  return curvalid;
}

QgsStringMap QgsAuthOAuth2Edit::configMap() const
{
  QgsStringMap configmap;
  bool ok = false;

  if ( onCustomTab() )
  {
    if ( !mOAuthConfigCustom || !mOAuthConfigCustom->isValid() )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to serialize OAuth config object: null or invalid object" ) );
      return configmap;
    }

    mOAuthConfigCustom->setQueryPairs( queryPairs() );

    QByteArray configtxt = mOAuthConfigCustom->saveConfigTxt( QgsAuthOAuth2Config::JSON, false, &ok );

    if ( !ok )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to serialize OAuth config object" ) );
      return configmap;
    }

    if ( configtxt.isEmpty() )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to serialize OAuth config object: content empty" ) );
      return configmap;
    }

    //###################### DO NOT LEAVE ME UNCOMMENTED #####################
    //QgsDebugMsg( QStringLiteral( "SAVE oauth2config configtxt: \n\n%1\n\n" ).arg( QString( configtxt ) ) );
    //###################### DO NOT LEAVE ME UNCOMMENTED #####################

    configmap.insert( QStringLiteral( "oauth2config" ), QString( configtxt ) );

    updateTokenCacheFile( mOAuthConfigCustom->persistToken() );
  }
  else if ( onDefinedTab() && !mDefinedId.isEmpty() )
  {
    configmap.insert( QStringLiteral( "definedid" ), mDefinedId );
    configmap.insert( QStringLiteral( "defineddirpath" ), leDefinedDirPath->text() );
    configmap.insert( QStringLiteral( "querypairs" ),
                      QgsAuthOAuth2Config::serializeFromVariant(
                        queryPairs(), QgsAuthOAuth2Config::JSON, false ) );
  }

  return configmap;
}

void QgsAuthOAuth2Edit::loadConfig( const QgsStringMap &configmap )
{
  clearConfig();

  mConfigMap = configmap;
  bool ok = false;

  //QgsDebugMsg( QStringLiteral( "oauth2config: " ).arg( configmap.value( QStringLiteral( "oauth2config" ) ) ) );

  if ( configmap.contains( QStringLiteral( "oauth2config" ) ) )
  {
    tabConfigs->setCurrentIndex( customTab() );
    QByteArray configtxt = configmap.value( QStringLiteral( "oauth2config" ) ).toUtf8();
    if ( !configtxt.isEmpty() )
    {
      //###################### DO NOT LEAVE ME UNCOMMENTED #####################
      //QgsDebugMsg( QStringLiteral( "LOAD oauth2config configtxt: \n\n%1\n\n" ).arg( QString( configtxt ) ) );
      //###################### DO NOT LEAVE ME UNCOMMENTED #####################

      if ( !mOAuthConfigCustom->loadConfigTxt( configtxt, QgsAuthOAuth2Config::JSON ) )
      {
        QgsDebugMsg( QStringLiteral( "FAILED to load OAuth2 config into object" ) );
      }

      //###################### DO NOT LEAVE ME UNCOMMENTED #####################
      //QVariantMap vmap = mOAuthConfigCustom->mappedProperties();
      //QByteArray vmaptxt = QgsAuthOAuth2Config::serializeFromVariant(vmap, QgsAuthOAuth2Config::JSON, true );
      //QgsDebugMsg( QStringLiteral( "LOAD oauth2config vmaptxt: \n\n%1\n\n" ).arg( QString( vmaptxt ) ) );
      //###################### DO NOT LEAVE ME UNCOMMENTED #####################

      // could only be loading defaults at this point
      loadFromOAuthConfig( mOAuthConfigCustom.get() );

      mPrevPersistToken = mOAuthConfigCustom->persistToken();
    }
    else
    {
      QgsDebugMsg( QStringLiteral( "FAILED to load OAuth2 config: empty config txt" ) );
    }
  }
  else if ( configmap.contains( QStringLiteral( "definedid" ) ) )
  {
    tabConfigs->setCurrentIndex( definedTab() );
    QString definedid = configmap.value( QStringLiteral( "definedid" ) );
    setCurrentDefinedConfig( definedid );
    if ( !definedid.isEmpty() )
    {
      if ( !configmap.value( QStringLiteral( "defineddirpath" ) ).isEmpty() )
      {
        // this will trigger a reload of dirs and a reselection of any existing defined id
        leDefinedDirPath->setText( configmap.value( QStringLiteral( "defineddirpath" ) ) );
      }
      else
      {
        QgsDebugMsg( QStringLiteral( "No custom defined dir path to load OAuth2 config" ) );
        selectCurrentDefinedConfig();
      }

      QByteArray querypairstxt = configmap.value( QStringLiteral( "querypairs" ) ).toUtf8();
      if ( !querypairstxt.isNull() && !querypairstxt.isEmpty() )
      {
        QVariantMap querypairsmap =
          QgsAuthOAuth2Config::variantFromSerialized( querypairstxt, QgsAuthOAuth2Config::JSON, &ok );
        if ( ok )
        {
          populateQueryPairs( querypairsmap );
        }
        else
        {
          QgsDebugMsg( QStringLiteral( "No query pairs to load OAuth2 config: failed to parse" ) );
        }
      }
      else
      {
        QgsDebugMsg( QStringLiteral( "No query pairs to load OAuth2 config: empty text" ) );
      }
    }
    else
    {
      QgsDebugMsg( QStringLiteral( "FAILED to load a defined ID for OAuth2 config" ) );
    }
  }

  validateConfig();
}

void QgsAuthOAuth2Edit::resetConfig()
{
  loadConfig( mConfigMap );
}

void QgsAuthOAuth2Edit::clearConfig()
{
  // restore defaults to config objs
  mOAuthConfigCustom->setToDefaults();

  mDefinedId.clear();

  clearQueryPairs();

  // clear any set predefined location
  leDefinedDirPath->clear();

  // reload predefined table
  loadDefinedConfigs();

  loadFromOAuthConfig( mOAuthConfigCustom.get() );
}

void QgsAuthOAuth2Edit::loadFromOAuthConfig( const QgsAuthOAuth2Config *config )
{
  if ( !config )
  {
    return;
  }

  // load relative to config type
  if ( config->configType() == QgsAuthOAuth2Config::Custom )
  {
    if ( config->isValid() )
    {
      tabConfigs->setCurrentIndex( customTab() );
    }
    pteDescription->setPlainText( config->description() );
    leRequestUrl->setText( config->requestUrl() );
    leTokenUrl->setText( config->tokenUrl() );
    leRefreshTokenUrl->setText( config->refreshTokenUrl() );
    leRedirectUrl->setText( config->redirectUrl() );
    spnbxRedirectPort->setValue( config->redirectPort() );
    leClientId->setText( config->clientId() );
    leClientSecret->setText( config->clientSecret() );
    leUsername->setText( config->username() );
    lePassword->setText( config->password() );
    leScope->setText( config->scope() );
    leApiKey->setText( config->apiKey() );

    // advanced
    chkbxTokenPersist->setChecked( config->persistToken() );
    cmbbxAccessMethod->setCurrentIndex( static_cast<int>( config->accessMethod() ) );

    spnbxRequestTimeout->setValue( config->requestTimeout() );

    populateQueryPairs( config->queryPairs() );

    updateGrantFlow( static_cast<int>( config->grantFlow() ) );

    // Dynamic Client Registration
    leRegAuthUrl->setText( config->regAuthUrl() );
    leRegAccessToken->setText( config->regAccessToken() );
    leRegRedirectUrl->setText( config->regRedirectUrl() );
    spnbxRegRedirectPort->setValue( config->regRedirectPort() );
    cmbbxRegTokenAuth->setCurrentIndex( static_cast<int>( config->regTokenAuth() ) );
    cmbbxRegGrantType->setCurrentIndex( static_cast<int>( config->regGrantType() ) );
    leRegClientName->setText( config->regClientName() );
    leRegScopes->setText( config->regScopes() );
    teRegContactInfo->setPlainText( config->regContactInfo() );
    cmbbxRegKeySet->setCurrentIndex( 0 );
  }

  validateConfig();
}

void QgsAuthOAuth2Edit::updateTokenCacheFile( bool curpersist ) const
{
  // default for unset persistToken in config and edit GUI is false
  if ( mPrevPersistToken == curpersist )
  {
    return;
  }

  if ( !parent() )
  {
    QgsDebugMsg( QStringLiteral( "Edit widget has no parent" ) );
    return;
  }

  QString authcfg = parentConfigId();
  if ( authcfg.isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "Auth config ID empty in ID widget of parent" ) );
    return;
  }

  QString localcachefile = QgsAuthOAuth2Config::tokenCachePath( authcfg, false );

  QString tempcachefile = QgsAuthOAuth2Config::tokenCachePath( authcfg, true );

  //QgsDebugMsg( QStringLiteral( "localcachefile: %1" ).arg( localcachefile ) );
  //QgsDebugMsg( QStringLiteral( "tempcachefile: %1" ).arg( tempcachefile ) );

  if ( curpersist )
  {
    // move cache file from temp dir to local
    if ( QFile::exists( localcachefile ) && !QFile::remove( localcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to delete local token cache file: %1" ).arg( localcachefile ) );
      return;
    }
    if ( QFile::exists( tempcachefile ) && !QFile::copy( tempcachefile, localcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to copy temp to local token cache file: %1 -> %2" ).arg( tempcachefile, localcachefile ) );
      return;
    }
    if ( QFile::exists( tempcachefile ) && !QFile::remove( tempcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to delete temp token cache file after copy: %1" ).arg( tempcachefile ) );
      return;
    }
  }
  else
  {
    // move cache file from local to temp
    if ( QFile::exists( tempcachefile ) && !QFile::remove( tempcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to delete temp token cache file: %1" ).arg( tempcachefile ) );
      return;
    }
    if ( QFile::exists( localcachefile ) && !QFile::copy( localcachefile, tempcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to copy local to temp token cache file: %1 -> %2" ).arg( localcachefile, tempcachefile ) );
      return;
    }
    if ( QFile::exists( localcachefile ) && !QFile::remove( localcachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to delete temp token cache file after copy: %1" ).arg( localcachefile ) );
      return;
    }
  }
}


void QgsAuthOAuth2Edit::tabIndexChanged( int indx )
{
  mCurTab = indx;
  validateConfig();
}


void QgsAuthOAuth2Edit::populateGrantFlows()
{
  cmbbxGrantFlow->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::AuthCode ),
                           static_cast<int>( QgsAuthOAuth2Config::AuthCode ) );
  cmbbxGrantFlow->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::Implicit ),
                           static_cast<int>( QgsAuthOAuth2Config::Implicit ) );
  cmbbxGrantFlow->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::ResourceOwner ),
                           static_cast<int>( QgsAuthOAuth2Config::ResourceOwner ) );
}


void QgsAuthOAuth2Edit::definedCustomDirChanged( const QString &path )
{
  QFileInfo pinfo( path );
  bool ok = pinfo.exists() || pinfo.isDir();

  leDefinedDirPath->setStyleSheet( ok ? QString() : QgsAuthGuiUtils::redTextStyleSheet() );
  updatePredefinedLocationsTooltip();

  if ( ok )
  {
    loadDefinedConfigs();
  }
}


void QgsAuthOAuth2Edit::softwareStatementJwtPathChanged( const QString &path )
{
  QFileInfo pinfo( path );
  bool ok = pinfo.exists() || pinfo.isFile();

  leSoftwareStatementJwtPath->setStyleSheet( ok ? QString() : QgsAuthGuiUtils::redTextStyleSheet() );

  if ( ok )
  {
    parseSoftwareStatement( path );
  }
}


void QgsAuthOAuth2Edit::setCurrentDefinedConfig( const QString &id )
{
  mDefinedId = id;
  QgsDebugMsg( QStringLiteral( "Set defined ID: %1" ).arg( id ) );
  validateConfig();
}

void QgsAuthOAuth2Edit::currentDefinedItemChanged( QListWidgetItem *cur, QListWidgetItem *prev )
{
  Q_UNUSED( prev )

  QgsDebugMsg( QStringLiteral( "Entered" ) );

  QString id = cur->data( Qt::UserRole ).toString();
  if ( !id.isEmpty() )
  {
    setCurrentDefinedConfig( id );
  }
}


void QgsAuthOAuth2Edit::selectCurrentDefinedConfig()
{
  if ( mDefinedId.isEmpty() )
  {
    return;
  }

  if ( !onDefinedTab() )
  {
    tabConfigs->setCurrentIndex( definedTab() );
  }

  lstwdgDefinedConfigs->selectionModel()->clearSelection();

  for ( int i = 0; i < lstwdgDefinedConfigs->count(); ++i )
  {
    QListWidgetItem *itm = lstwdgDefinedConfigs->item( i );

    if ( itm->data( Qt::UserRole ).toString() == mDefinedId )
    {
      lstwdgDefinedConfigs->setCurrentItem( itm, QItemSelectionModel::Select );
      break;
    }
  }
}

void QgsAuthOAuth2Edit::getDefinedCustomDir()
{
  QString extradir = QFileDialog::getExistingDirectory( this, tr( "Select extra directory to parse" ),
                     QDir::homePath(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks );
  this->raise();
  this->activateWindow();

  if ( extradir.isEmpty() )
  {
    return;
  }
  leDefinedDirPath->setText( extradir );
}

void QgsAuthOAuth2Edit::getSoftStatementDir()
{
  QString softStatementFile = QFileDialog::getOpenFileName( this, tr( "Select software statement file" ),
                              QDir::homePath(), tr( "JSON Web Token (*.jwt)" ) );
  this->raise();
  this->activateWindow();

  if ( softStatementFile.isEmpty() )
  {
    return;
  }
  leSoftwareStatementJwtPath->setText( softStatementFile );
}

void QgsAuthOAuth2Edit::initConfigObjs()
{
  mOAuthConfigCustom = qgis::make_unique<QgsAuthOAuth2Config>( nullptr );
  mOAuthConfigCustom->setConfigType( QgsAuthOAuth2Config::Custom );
  mOAuthConfigCustom->setToDefaults();
}


bool QgsAuthOAuth2Edit::hasTokenCacheFile()
{
  QString authcfg = parentConfigId();
  if ( authcfg.isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "Auth config ID empty in ID widget of parent" ) );
    return false;
  }

  return ( QFile::exists( QgsAuthOAuth2Config::tokenCachePath( authcfg, false ) )
           || QFile::exists( QgsAuthOAuth2Config::tokenCachePath( authcfg, true ) ) );
}

//slot
void QgsAuthOAuth2Edit::removeTokenCacheFile()
{
  QString authcfg = parentConfigId();
  if ( authcfg.isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "Auth config ID empty in ID widget of parent" ) );
    return;
  }

  const QStringList cachefiles = QStringList()
                                 << QgsAuthOAuth2Config::tokenCachePath( authcfg, false )
                                 << QgsAuthOAuth2Config::tokenCachePath( authcfg, true );

  for ( const QString &cachefile : cachefiles )
  {
    if ( QFile::exists( cachefile ) && !QFile::remove( cachefile ) )
    {
      QgsDebugMsg( QStringLiteral( "Remove token cache file FAILED for authcfg %1: %2" ).arg( authcfg, cachefile ) );
    }
  }
  btnTokenClear->setEnabled( hasTokenCacheFile() );
}

void QgsAuthOAuth2Edit::updateDefinedConfigsCache()
{
  QString extradir = leDefinedDirPath->text();
  mDefinedConfigsCache.clear();
  mDefinedConfigsCache = QgsAuthOAuth2Config::mappedOAuth2ConfigsCache( this, extradir );
}

void QgsAuthOAuth2Edit::loadDefinedConfigs()
{
  whileBlocking( lstwdgDefinedConfigs )->clear();
  updateDefinedConfigsCache();
  updatePredefinedLocationsTooltip();

  QgsStringMap::const_iterator i = mDefinedConfigsCache.constBegin();
  while ( i != mDefinedConfigsCache.constEnd() )
  {
    QgsAuthOAuth2Config *config = new QgsAuthOAuth2Config( this );
    if ( !config->loadConfigTxt( i.value().toUtf8(), QgsAuthOAuth2Config::JSON ) )
    {
      QgsDebugMsg( QStringLiteral( "FAILED to load config for ID: %1" ).arg( i.key() ) );
      config->deleteLater();
      continue;
    }

    QString grantflow = QgsAuthOAuth2Config::grantFlowString( config->grantFlow() );

    QString name = QStringLiteral( "%1 (%2): %3" )
                   .arg( config->name(), grantflow, config->description() );

    QString tip = tr( "ID: %1\nGrant flow: %2\nDescription: %3" )
                  .arg( i.key(), grantflow, config->description() );

    QListWidgetItem *itm = new QListWidgetItem( lstwdgDefinedConfigs );
    itm->setText( name );
    itm->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable );
    itm->setData( Qt::UserRole, QVariant( i.key() ) );
    itm->setData( Qt::ToolTipRole, QVariant( tip ) );
    lstwdgDefinedConfigs->addItem( itm );

    config->deleteLater();
    ++i;
  }

  if ( lstwdgDefinedConfigs->count() == 0 )
  {
    QListWidgetItem *itm = new QListWidgetItem( lstwdgDefinedConfigs );
    itm->setText( tr( "No predefined configurations found on disk" ) );
    QFont f( itm->font() );
    f.setItalic( true );
    itm->setFont( f );
    itm->setFlags( Qt::NoItemFlags );
    lstwdgDefinedConfigs->addItem( itm );
  }

  selectCurrentDefinedConfig();
}

bool QgsAuthOAuth2Edit::onCustomTab() const
{
  return mCurTab == customTab();
}

bool QgsAuthOAuth2Edit::onRegistrationTab() const
{
    return mCurTab == registrationTab();
}

bool QgsAuthOAuth2Edit::onDefinedTab() const
{
  return mCurTab == definedTab();
}

bool QgsAuthOAuth2Edit::onStatementTab() const
{
  return mCurTab == statementTab();
}

void QgsAuthOAuth2Edit::updateGrantFlow( int indx )
{
  if ( cmbbxGrantFlow->currentIndex() != indx )
  {
    whileBlocking( cmbbxGrantFlow )->setCurrentIndex( indx );
  }

  QgsAuthOAuth2Config::GrantFlow flow =
    static_cast<QgsAuthOAuth2Config::GrantFlow>( cmbbxGrantFlow->itemData( indx ).toInt() );
  mOAuthConfigCustom->setGrantFlow( flow );

  // bool authcode = ( flow == QgsAuthOAuth2Config::AuthCode );
  bool implicit = ( flow == QgsAuthOAuth2Config::Implicit );
  bool resowner = ( flow == QgsAuthOAuth2Config::ResourceOwner );

  lblRequestUrl->setVisible( !resowner );
  leRequestUrl->setVisible( !resowner );
  if ( resowner )
    leRequestUrl->setText( QString() );

  lblRedirectUrl->setVisible( !resowner );
  frameRedirectUrl->setVisible( !resowner );

  lblClientSecret->setVisible( !implicit );
  leClientSecret->setVisible( !implicit );
  if ( implicit )
    leClientSecret->setText( QString() );

  leClientId->setPlaceholderText( resowner ? tr( "Optional" ) : tr( "Required" ) );
  leClientSecret->setPlaceholderText( resowner ? tr( "Optional" ) : tr( "Required" ) );


  lblUsername->setVisible( resowner );
  leUsername->setVisible( resowner );
  if ( !resowner )
    leUsername->setText( QString() );
  lblPassword->setVisible( resowner );
  lePassword->setVisible( resowner );
  if ( !resowner )
    lePassword->setText( QString() );
}

void QgsAuthOAuth2Edit::exportOAuthConfig()
{
  if ( !onCustomTab() || !mValid )
  {
    return;
  }

  QSettings settings;
  QString recentdir = settings.value( QStringLiteral( "UI/lastAuthSaveFileDir" ), QDir::homePath() ).toString();
  QString configpath = QFileDialog::getSaveFileName(
                         this, tr( "Save OAuth2 Config File" ), recentdir, QStringLiteral( "OAuth2 config files (*.json)" ) );
  this->raise();
  this->activateWindow();

  if ( configpath.isEmpty() )
  {
    return;
  }
  settings.setValue( QStringLiteral( "UI/lastAuthSaveFileDir" ), QFileInfo( configpath ).absoluteDir().path() );

  // give it a kind of random id for re-importing
  mOAuthConfigCustom->setId( QgsApplication::authManager()->uniqueConfigId() );

  mOAuthConfigCustom->setQueryPairs( queryPairs() );

  if ( mParentName && !mParentName->text().isEmpty() )
  {
    mOAuthConfigCustom->setName( mParentName->text() );
  }

  if ( !QgsAuthOAuth2Config::writeOAuth2Config( configpath, mOAuthConfigCustom.get(),
       QgsAuthOAuth2Config::JSON, true ) )
  {
    QgsDebugMsg( QStringLiteral( "FAILED to export OAuth2 config file" ) );
  }
  // clear temp changes
  mOAuthConfigCustom->setId( QString() );
  mOAuthConfigCustom->setName( QString() );
}


void QgsAuthOAuth2Edit::importOAuthConfig()
{
  if ( !onCustomTab() )
  {
    return;
  }

  QString configfile =
    QgsAuthGuiUtils::getOpenFileName( this, tr( "Select OAuth2 Config File" ), QStringLiteral( "OAuth2 config files (*.json)" ) );
  this->raise();
  this->activateWindow();

  QFileInfo importinfo( configfile );
  if ( configfile.isEmpty() || !importinfo.exists() )
  {
    return;
  }

  QByteArray configtxt;
  QFile cfile( configfile );
  bool ret = cfile.open( QIODevice::ReadOnly | QIODevice::Text );
  if ( ret )
  {
    configtxt = cfile.readAll();
  }
  else
  {
    QgsDebugMsg( QStringLiteral( "FAILED to open config for reading: %1" ).arg( configfile ) );
    cfile.close();
    return;
  }
  cfile.close();

  if ( configtxt.isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "EMPTY read of config: %1" ).arg( configfile ) );
    return;
  }

  QgsStringMap configmap;
  configmap.insert( QStringLiteral( "oauth2config" ), QString( configtxt ) );
  loadConfig( configmap );
}


void QgsAuthOAuth2Edit::descriptionChanged()
{
    mOAuthConfigCustom->setDescription( pteDescription->toPlainText() );
}

void QgsAuthOAuth2Edit::regContactInfoChanged()
{
    mOAuthConfigCustom->setRegContactInfo( teRegContactInfo->toPlainText() );
}

void QgsAuthOAuth2Edit::updateConfigRegKeySet( int indx )
{
    Q_UNUSED(indx)
    QString data = cmbbxRegKeySet->itemData(indx).toString();
    mOAuthConfigCustom->setRegKeySet( data );
}

void QgsAuthOAuth2Edit::loadAvailableConfigs()
{
  mConfigs.clear();
  mConfigs = QgsApplication::authManager()->availableAuthMethodConfigs( QString() );
}

void QgsAuthOAuth2Edit::populateRegKeySet()
{
  loadAvailableConfigs();

  cmbbxRegKeySet->blockSignals( true );
  cmbbxRegKeySet->clear();
  cmbbxRegKeySet->addItem( tr( "No Token Key Set Selected" ), "0" );

  QgsStringMap sortmap;
  QgsAuthMethodConfigsMap::const_iterator cit = mConfigs.constBegin();
  for ( cit = mConfigs.constBegin(); cit != mConfigs.constEnd(); ++cit )
  {
    QgsAuthMethodConfig config = cit.value();
    if ( config.method() == QString( "PKI-PKCS#12" ) )
        sortmap.insert( QStringLiteral( "%1 (%2)" ).arg( config.name(), config.method() ), cit.key() );
  }

  QgsStringMap::const_iterator sm = sortmap.constBegin();
  for ( sm = sortmap.constBegin(); sm != sortmap.constEnd(); ++sm )
  {
    cmbbxRegKeySet->addItem( sm.key(), sm.value() );
  }
  cmbbxRegKeySet->blockSignals( false );
}

void QgsAuthOAuth2Edit::setRegAuthUrl()
{
    mOAuthConfigCustom->setRegAuthUrl(leRegAuthUrl->text());
    btnRegRegister->setEnabled( QUrl(leRegAuthUrl->text()).isValid() );
}

void QgsAuthOAuth2Edit::populateAccessMethods()
{
  cmbbxAccessMethod->addItem( QgsAuthOAuth2Config::accessMethodString( QgsAuthOAuth2Config::Header ),
                              static_cast<int>( QgsAuthOAuth2Config::Header ) );
  cmbbxAccessMethod->addItem( QgsAuthOAuth2Config::accessMethodString( QgsAuthOAuth2Config::Form ),
                              static_cast<int>( QgsAuthOAuth2Config::Form ) );
  cmbbxAccessMethod->addItem( QgsAuthOAuth2Config::accessMethodString( QgsAuthOAuth2Config::Query ),
                              static_cast<int>( QgsAuthOAuth2Config::Query ) );
}


void QgsAuthOAuth2Edit::updateConfigAccessMethod( int indx )
{
  mOAuthConfigCustom->setAccessMethod( static_cast<QgsAuthOAuth2Config::AccessMethod>( indx ) );
}

void QgsAuthOAuth2Edit::addQueryPairRow( const QString &key, const QString &val )
{
  int rowCnt = tblwdgQueryPairs->rowCount();
  tblwdgQueryPairs->insertRow( rowCnt );

  Qt::ItemFlags itmFlags = Qt::ItemIsEnabled | Qt::ItemIsSelectable
                           | Qt::ItemIsEditable | Qt::ItemIsDropEnabled;

  QTableWidgetItem *keyItm = new QTableWidgetItem( key );
  keyItm->setFlags( itmFlags );
  tblwdgQueryPairs->setItem( rowCnt, 0, keyItm );

  QTableWidgetItem *valItm = new QTableWidgetItem( val );
  keyItm->setFlags( itmFlags );
  tblwdgQueryPairs->setItem( rowCnt, 1, valItm );
}


void QgsAuthOAuth2Edit::populateQueryPairs( const QVariantMap &querypairs, bool append )
{
  if ( !append )
  {
    clearQueryPairs();
  }

  QVariantMap::const_iterator i = querypairs.constBegin();
  while ( i != querypairs.constEnd() )
  {
    addQueryPairRow( i.key(), i.value().toString() );
    ++i;
  }
}

void QgsAuthOAuth2Edit::populateRegTokenAuthMethods()
{
    cmbbxRegTokenAuth->addItem( QgsAuthOAuth2Config::regTokenAuthString( QgsAuthOAuth2Config::taNone ),
                                static_cast<int>( QgsAuthOAuth2Config::taNone ) );
    cmbbxRegTokenAuth->addItem( QgsAuthOAuth2Config::regTokenAuthString( QgsAuthOAuth2Config::taClientSecretPost ),
                                static_cast<int>( QgsAuthOAuth2Config::taClientSecretPost ) );
    cmbbxRegTokenAuth->addItem( QgsAuthOAuth2Config::regTokenAuthString( QgsAuthOAuth2Config::taClientSecretBasic ),
                                static_cast<int>( QgsAuthOAuth2Config::taClientSecretBasic ) );
}

void QgsAuthOAuth2Edit::updateConfigRegTokenAuthMethod( int indx )
{
    mOAuthConfigCustom->setRegTokenAuth( static_cast<QgsAuthOAuth2Config::TokenAuth>( indx ) );
}

void QgsAuthOAuth2Edit::populateRegGrantType()
{
  cmbbxRegGrantType->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::AuthCode ),
                              static_cast<int>( QgsAuthOAuth2Config::AuthCode ) );
  cmbbxRegGrantType->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::Implicit ),
                              static_cast<int>( QgsAuthOAuth2Config::Implicit ) );
  cmbbxRegGrantType->addItem( QgsAuthOAuth2Config::grantFlowString( QgsAuthOAuth2Config::ResourceOwner ),
                              static_cast<int>( QgsAuthOAuth2Config::ResourceOwner ) );
}

void QgsAuthOAuth2Edit::updateConfigRegGrantType( int indx )
{
    mOAuthConfigCustom->setRegGrantType( static_cast<QgsAuthOAuth2Config::GrantFlow>( indx ) );
}

void QgsAuthOAuth2Edit::queryTableSelectionChanged()
{
  bool hassel = tblwdgQueryPairs->selectedItems().count() > 0;
  btnRemoveQueryPair->setEnabled( hassel );
}

void QgsAuthOAuth2Edit::updateConfigQueryPairs()
{
  mOAuthConfigCustom->setQueryPairs( queryPairs() );
}

QVariantMap QgsAuthOAuth2Edit::queryPairs() const
{
  QVariantMap querypairs;
  for ( int i = 0; i < tblwdgQueryPairs->rowCount(); ++i )
  {
    if ( tblwdgQueryPairs->item( i, 0 )->text().isEmpty() )
    {
      continue;
    }
    querypairs.insert( tblwdgQueryPairs->item( i, 0 )->text(),
                       QVariant( tblwdgQueryPairs->item( i, 1 )->text() ) );
  }
  return querypairs;
}


void QgsAuthOAuth2Edit::addQueryPair()
{
  addQueryPairRow( QString(), QString() );
  tblwdgQueryPairs->setFocus();
  tblwdgQueryPairs->setCurrentCell( tblwdgQueryPairs->rowCount() - 1, 0 );
  tblwdgQueryPairs->edit( tblwdgQueryPairs->currentIndex() );
}


void QgsAuthOAuth2Edit::removeQueryPair()
{
  tblwdgQueryPairs->removeRow( tblwdgQueryPairs->currentRow() );
}


void QgsAuthOAuth2Edit::clearQueryPairs()
{
  for ( int i = tblwdgQueryPairs->rowCount(); i > 0 ; --i )
  {
    tblwdgQueryPairs->removeRow( i - 1 );
  }
}

void QgsAuthOAuth2Edit::parseSoftwareStatement( const QString &path )
{
  QFile file( path );
  QByteArray softwareStatementBase64;
  if ( file.open( QIODevice::ReadOnly | QIODevice::Text ) )
  {
    softwareStatementBase64 = file.readAll();
  }
  if ( softwareStatementBase64.isEmpty() )
  {
    QgsDebugMsg( QStringLiteral( "Error software statement is empty: %1" ).arg( path ) );
    file.close();
    return;
  }
  mRegistrationEndpoint = QString();
  file.close();
  mSoftwareStatement.insert( QStringLiteral( "software_statement" ), softwareStatementBase64 );
  QList<QByteArray> payloadParts( softwareStatementBase64.split( '.' ) );
  if ( payloadParts.count() < 2 )
  {
    QgsDebugMsg( QStringLiteral( "Error parsing JSON: base64 decode returned less than 2 parts" ) );
    return;
  }
  QByteArray payload = payloadParts[1];
  QByteArray decoded = QByteArray::fromBase64( payload/*, QByteArray::Base64UrlEncoding*/ );
  QByteArray errStr;
  bool res = false;
  const QMap<QString, QVariant> jsonData = QJsonWrapper::parseJson( decoded, &res, &errStr ).toMap();
  if ( !res )
  {
    QgsDebugMsg( QStringLiteral( "Error parsing JSON: %1" ).arg( QString( errStr ) ) );
    return;
  }
  if ( jsonData.contains( QStringLiteral( "grant_types" ) ) && jsonData.contains( QStringLiteral( "redirect_uris" ) ) )
  {
    const QStringList grantTypes( jsonData[QStringLiteral( "grant_types" ) ].toStringList() );
    if ( !grantTypes.isEmpty( ) )
    {
      QString grantType = grantTypes[0];
      if ( grantType == QLatin1String( "authorization_code" ) )
      {
        updateGrantFlow( static_cast<int>( QgsAuthOAuth2Config::AuthCode ) );
      }
      else
      {
        updateGrantFlow( static_cast<int>( QgsAuthOAuth2Config::ResourceOwner ) );
      }
    }
    //Set redirect_uri
    const QStringList  redirectUris( jsonData[QStringLiteral( "redirect_uris" ) ].toStringList() );
    if ( !redirectUris.isEmpty( ) )
    {
      QString redirectUri = redirectUris[0];
      leRedirectUrl->setText( redirectUri );
    }
  }
  else
  {
    QgsDebugMsgLevel( QStringLiteral( "Error software statement is invalid: %1" ).arg( path ), 4 );
    return;
  }
  if ( jsonData.contains( QStringLiteral( "registration_endpoint" ) ) )
  {
    mRegistrationEndpoint = jsonData[QStringLiteral( "registration_endpoint" )].toString();
    leSoftwareStatementConfigUrl->setText( mRegistrationEndpoint );
  }
  QgsDebugMsgLevel( QStringLiteral( "JSON: %1" ).arg( QString::fromLocal8Bit( decoded.data() ) ), 4 );
}

void QgsAuthOAuth2Edit::configReplyFinished()
{
  qDebug() << "QgsAuthOAuth2Edit::onConfigReplyFinished";
  QNetworkReply *configReply = qobject_cast<QNetworkReply *>( sender() );
  if ( configReply->error() == QNetworkReply::NoError )
  {
    QByteArray replyData = configReply->readAll();
    QByteArray errStr;
    bool res = false;
    QVariantMap config = QJsonWrapper::parseJson( replyData, &res, &errStr ).toMap();

    if ( !res )
    {
      QgsDebugMsg( QStringLiteral( "Error parsing JSON: %1" ).arg( QString( errStr ) ) );
      return;
    }
    // I haven't found any docs about the content of this confg JSON file
    // I assume that registration_endpoint is all that it MUST contain.
    // But we also MAY have other optional information here
    if ( config.contains( QStringLiteral( "registration_endpoint" ) ) )
    {
      if ( config.contains( QStringLiteral( "authorization_endpoint" ) ) )
        leRequestUrl->setText( config.value( QStringLiteral( "authorization_endpoint" ) ).toString() );
      if ( config.contains( QStringLiteral( "token_endpoint" ) ) )
        leTokenUrl->setText( config.value( QStringLiteral( "token_endpoint" ) ).toString() );

      registerSoftStatement( config.value( QStringLiteral( "registration_endpoint" ) ).toString() );
    }
    else
    {
      QString errorMsg = tr( "Downloading configuration failed with error: %1" ).arg( configReply->errorString() );
      QgsMessageLog::logMessage( errorMsg, QStringLiteral( "OAuth2" ), Qgis::Critical );
    }
  }
  mDownloading = false;
  configReply->deleteLater();
}

QgsAuthOAuth2Config::GrantFlow QgsAuthOAuth2Edit::getFlowFromMetadata(const QString &grantMetadataType)
{
    if ( grantMetadataType == QStringLiteral( "authorization_code" ) )
        return QgsAuthOAuth2Config::AuthCode;
    if ( grantMetadataType == QStringLiteral( "implicit" ) )
        return QgsAuthOAuth2Config::Implicit;
    else
        return QgsAuthOAuth2Config::ResourceOwner;
}

void QgsAuthOAuth2Edit::registerReplyFinished()
{
  //JSV todo
  //better error handling
  qDebug() << "QgsAuthOAuth2Edit::onRegisterReplyFinished";
  QNetworkReply *registerReply = qobject_cast<QNetworkReply *>( sender() );
  if ( registerReply->error() == QNetworkReply::NoError )
  {
    QByteArray replyData = registerReply->readAll();
    QByteArray errStr;
    bool res = false;
    QVariantMap clientInfo = QJsonWrapper::parseJson( replyData, &res, &errStr ).toMap();

    // According to RFC 7591 sec. 3.2.1.  Client Information Response the only
    // required field is client_id
    leClientId->setText( clientInfo.value( QStringLiteral( "client_id" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "client_secret" ) ) )
      leClientSecret->setText( clientInfo.value( QStringLiteral( "client_secret" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "authorization_endpoint" ) ) )
      leRequestUrl->setText( clientInfo.value( QStringLiteral( "authorization_endpoint" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "token_endpoint" ) ) )
      leTokenUrl->setText( clientInfo.value( QStringLiteral( "token_endpoint" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "scopes" ) ) )
        leScope->setText( clientInfo.value( QStringLiteral( "scopes" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "scope" ) ) )
        leScope->setText( clientInfo.value( QStringLiteral( "scope" ) ).toString() );
    if ( clientInfo.contains( QStringLiteral( "grant_types") ) )
    {
        QString grantType = clientInfo.value( QStringLiteral( "grant_types" ) ).toStringList()[0];
        this->updateGrantFlow( static_cast<int>( this->getFlowFromMetadata( grantType ) ) );
    }
    if ( !mClientRegistrationEndpoint.isEmpty() )
    {
        spnbxRedirectPort->setValue( mOAuthConfigCustom->regRedirectPort() );
        leRedirectUrl->setText( mOAuthConfigCustom->regRedirectUrl() );
    }

    tabConfigs->setCurrentIndex( 0 );
  }
  else
  {
    QString errorMsg = QStringLiteral( "Client registration failed with error: %1" ).arg( registerReply->errorString() );
    QgsMessageLog::logMessage( errorMsg, QStringLiteral( "OAuth2" ), Qgis::Critical );
  }
  mDownloading = false;
  registerReply->deleteLater();
}

void QgsAuthOAuth2Edit::networkError( QNetworkReply::NetworkError error )
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *>( sender() );
  qWarning() << "QgsAuthOAuth2Edit::onNetworkError: " << error << ": " << reply->errorString();
  QString errorMsg = QStringLiteral( "Network error: %1" ).arg( reply->errorString() );
  QgsMessageLog::logMessage( errorMsg, QStringLiteral( "OAuth2" ), Qgis::Critical );
  qDebug() << "QgsAuthOAuth2Edit::onNetworkError: " << reply->readAll();
}


void QgsAuthOAuth2Edit::registerSoftStatement( const QString &registrationUrl )
{
  QUrl regUrl( registrationUrl );
  if ( !regUrl.isValid() )
  {
    qWarning() << "Registration url is not valid";
    return;
  }
  QByteArray errStr;
  bool res = false;
  QByteArray json = QJsonWrapper::toJson( QVariant( mSoftwareStatement ), &res, &errStr );
  QNetworkRequest registerRequest( regUrl );
  QgsSetRequestInitiatorClass( registerRequest, QStringLiteral( "QgsAuthOAuth2Edit" ) );
  registerRequest.setHeader( QNetworkRequest::ContentTypeHeader, QLatin1String( "application/json" ) );
  QNetworkReply *registerReply;
  // For testability: use GET if protocol is file://
  if ( regUrl.scheme() == QLatin1String( "file" ) )
    registerReply = QgsNetworkAccessManager::instance()->get( registerRequest );
  else
    registerReply = QgsNetworkAccessManager::instance()->post( registerRequest, json );
  mDownloading = true;
  connect( registerReply, &QNetworkReply::finished, this, &QgsAuthOAuth2Edit::registerReplyFinished, Qt::QueuedConnection );
  connect( registerReply, qgis::overload<QNetworkReply::NetworkError>::of( &QNetworkReply::error ), this, &QgsAuthOAuth2Edit::networkError, Qt::QueuedConnection );
}

void QgsAuthOAuth2Edit::getSoftwareStatementConfig()
{
  if ( !mRegistrationEndpoint.isEmpty() )
  {
    registerSoftStatement( mRegistrationEndpoint );
  }
  else
  {
    QString config = leRegAuthUrl->text();
    QUrl configUrl( config );
    QNetworkRequest configRequest( configUrl );
    QgsSetRequestInitiatorClass( configRequest, QStringLiteral( "QgsAuthOAuth2Edit" ) );
    QNetworkReply *configReply = QgsNetworkAccessManager::instance()->get( configRequest );
    mDownloading = true;
    connect( configReply, &QNetworkReply::finished, this, &QgsAuthOAuth2Edit::configReplyFinished, Qt::QueuedConnection );
    connect( configReply, qgis::overload<QNetworkReply::NetworkError>::of( &QNetworkReply::error ), this, &QgsAuthOAuth2Edit::networkError, Qt::QueuedConnection );
  }
}

// static
QString const QgsAuthOAuth2Edit::regResponseTypeMetadataString(QgsAuthOAuth2Config::GrantFlow value)
{
    switch ( value )
    {
        case QgsAuthOAuth2Config::AuthCode:
            return QString( "code" );
        case QgsAuthOAuth2Config::Implicit:
            return QString( "token" );
        case QgsAuthOAuth2Config::ResourceOwner:
        default:
            return QString( "none" );
    }
}

QByteArray QgsAuthOAuth2Edit::parseDer( const QByteArray &der, int *pPos, QString *pJson, char *pLastDerType )
{
    int pos = *pPos;
    char derType = der.at(pos++);
    QByteArray value;
    if ( ( derType & 32 ) == 32 )
    {
        // Constructed Type
        *pLastDerType = derType;
        if ( ( derType & 31 ) == 16 )
        {
            // Sequence
            int derLength = retrieveDerValue( der, &pos, &value );
            bool first = pJson->length() == 0;
            pJson->append( first ? "[" : "{" );
            QString closeSequence = first ? "]" : "}";

            int valuePos = 0;
            QByteArray newValue = value;
            while( valuePos < ( newValue.length() - 1 ) )
            {
                if ( *pLastDerType == '\x02' ) pJson->append( "," );
                newValue = parseDer( newValue, &valuePos, pJson, pLastDerType );
            }
            pJson->append( closeSequence );
            pos += derLength;
            if( pos < der.length() )
            {
                pJson->append( "," );
            }

            *pLastDerType = derType;
            while( pos < der.length() )
            {
                if ( *pLastDerType == '\x02' ) pJson->append( "," );
                newValue = parseDer( der, &pos, pJson, pLastDerType );
            }
            value = der;
        }
    }
    else if ( derType == 6 )
    {
        // Object Identifier
        *pLastDerType = derType;
        int componentLength = static_cast<int>( der.at( pos++ ) );
        if ( componentLength >= 6 )
        {
            QByteArray rsa = QByteArrayLiteral("\x2a\x86\x48\x86\xf7\x0d");
            QByteArray algorithm = der.mid( pos, 6 );
            pos += 6;
            if ( algorithm == rsa )
            {
                // RSA Algorithm
                if (componentLength >= 9 )
                {
                    QByteArray pkcs1Encrypt = QByteArrayLiteral("\x01\x01\x01");
                    QByteArray test = der.mid( pos, 3 );
                    pos += 3;
                    if ( test == pkcs1Encrypt ) {
                        // KCS-1 Encryptio
                        pJson->append( "\"rsaEncryption\": " );
                        value = der.mid( pos );
                        pos = 0;
                    }
                }
            }
        }
    }
    else if ( derType == 5 )
    {
        // NULL Value
        *pLastDerType = derType;
        value = der.mid( pos, 1 );
        pos = 0;
        pJson->append( "\"\"" );
    }
    else if ( derType == 3 )
    {
        // Bit String containing RSA Public Key
        *pLastDerType = derType;
        int derLength = retrieveDerValue( der, &pos, &value) - 1;
        int bitPos = 0;
        QByteArray newValue = value.mid( 1, derLength );

        value = parseDer( newValue, &bitPos, pJson, pLastDerType );
        pos += derLength + 1;
        value = der;
    }
    else if ( derType == 2 )
    {
        *pLastDerType = derType;
        int derLength = retrieveDerValue( der, &pos, &value);
        int firstValue = static_cast<int>( value.at(0) );
        QByteArray newValue = firstValue == 0 ? value.mid( 1 ) : value;
        QByteArray base64 = newValue.toBase64(QByteArray::Base64UrlEncoding);
        if ( firstValue == 0 ) pJson->append( "\"n\": \"" );
        else pJson->append( "\"e\": \"" );
        pJson->append( base64 );
        pJson->append( "\"" );
        pos += derLength;
        value = der;
    }

    *pPos = pos;
    return value;
}

int QgsAuthOAuth2Edit::retrieveDerValue(const QByteArray &der, int *pPos, QByteArray *pValue)
{
    int pos = *pPos;
    int derLength= static_cast<int>( der.at( pos++ ) );

    if ( ( derLength & 128 ) == 128 )
    {
        int lengthSize = derLength & 127;
        QByteArray buffer = der.mid( pos, lengthSize );
        pos += lengthSize;
        derLength = 0;
        for ( int i = 0; i < lengthSize; i++ )
        {
            derLength <<= 8;
            derLength += static_cast<int>( buffer.at( i ) );
        }
        *pValue = der.mid( pos, derLength );
    }
    else
    {
        *pValue = der.mid( pos, derLength );
    }

    *pPos = pos;
    return derLength;
}

QString QgsAuthOAuth2Edit::loadPkcs12Config( const QString &authcfg )
{
    QgsAuthMethodConfig mconfig;

    if ( !QgsApplication::authManager()->loadAuthenticationConfig( authcfg, mconfig, true ) )
    {
        QgsDebugMsg( QStringLiteral( "PKI bundle for authcfg %1: FAILED to retrieve config" ).arg( authcfg ) );
        // return bundle;
    }

    QStringList bundlelist = QgsAuthCertUtils::pkcs12BundleToPem( mconfig.config( QStringLiteral( "bundlepath" ) ),
            mconfig.config( QStringLiteral( "bundlepass" ) ), false );

    if ( bundlelist.isEmpty() || bundlelist.size() < 2 )
    {
        QgsDebugMsg( QStringLiteral( "PKI bundle for authcfg %1: insert FAILED, PKCS#12 bundle parsing failed" ).arg( authcfg ) );
        //return bundle;
    }

    // init client cert
    // Note: if this is not valid, no sense continuing
    QSslCertificate clientcert( bundlelist.at( 0 ).toLatin1() );
    if ( !QgsAuthCertUtils::certIsViable( clientcert ) )
    {
        QgsDebugMsg( QStringLiteral( "PKI bundle for authcfg %1: insert FAILED, client cert is not viable" ).arg( authcfg ) );
        //return bundle;
    }

    QSslKey publicKey = clientcert.publicKey();
    QByteArray der = publicKey.toDer();
    int derPos = 0;
    QString json;
    char lastDerType = '\x00';
    parseDer( der, &derPos, &json, &lastDerType );
    return json;
}

void QgsAuthOAuth2Edit::clientRegistration( const QString &registrationUrl )
{
    QUrl regUrl( registrationUrl );
    if ( !regUrl.isValid() )
    {
        qWarning() << "Registration url is not valid";
        return;
    }
    QByteArray errStr;
    bool res = false;
    QVariantMap map;
    QString localhost;
    localhost.reserve( 22 + mOAuthConfigCustom->regRedirectUrl().length() );
    localhost.append( "http://127.0.0.1:" );
    localhost.append( QString::number( mOAuthConfigCustom->regRedirectPort() ) );
    localhost.append( "/" );

    QVariantList redirectUris;
    QString redirectUri;
    redirectUri.reserve( 22 + mOAuthConfigCustom->regRedirectUrl().length() );
    redirectUri.append( localhost );
    redirectUri.append( mOAuthConfigCustom->regRedirectUrl() );
    redirectUris.append( redirectUri );

    QVariantList grantTypes;
    grantTypes.append( mOAuthConfigCustom->regGrantTypeMetadataString( mOAuthConfigCustom->regGrantType() ) );

    QVariantList responseTypes;
    responseTypes.append(this->regResponseTypeMetadataString( mOAuthConfigCustom->regGrantType() ) );

    map.insert( "redirect_uris", redirectUris );
    map.insert( "token_endpoint_auth_method",
            mOAuthConfigCustom->regTokenAuthMetadataString( mOAuthConfigCustom->regTokenAuth() ) );
    map.insert( "grant_types", grantTypes );
    if( responseTypes[0] != QString("none") ) map.insert( "response_types", responseTypes );
    map.insert( "client_name", mOAuthConfigCustom->regClientName() );
    map.insert( "client_uri", "https://qgis.org/en/site/");
    map.insert( "logo_uri", "https://qgis.org/en/_static/images/trademark.png");
    map.insert( "scope", mOAuthConfigCustom->regScopes() );
    map.insert( "contacts", mOAuthConfigCustom->regContactInfo().split("\n") );

    QString tosUri;
    tosUri.reserve( localhost.length() + 3 );
    tosUri.append( localhost );
    tosUri.append( "tos" );
    map.insert( "tos_uri", tosUri );
    QString policyUri;
    policyUri.reserve( localhost.length() + 5 );
    policyUri.append( localhost );
    policyUri.append( "policy" );
    map.insert( "policy_uri", policyUri );
    map.insert( "software_id", "54cdcc00-cc4e-4652-aa0e-84f5b4b89460" );
    map.insert( "software_version", Qgis::version() );

    if ( cmbbxRegKeySet->currentIndex() != 0 )
    {
        QString jsonString = loadPkcs12Config( cmbbxRegKeySet->itemData( cmbbxRegKeySet->currentIndex() ).toString() );
        QJsonDocument jsonDocument = QJsonDocument::fromJson( jsonString.toUtf8() );
        QJsonArray jsonArray = jsonDocument.array();
        QVariantList jwks;
        QVariantMap jwk;
        jwk.insert( "kty", "RSA" );
        jwk.insert( "use", "enc" );
        jwk.insert( "key_ops", "wrapKey");
        jwk.insert( "n", jsonArray[1].toObject()["n"].toString() );
        jwk.insert( "e", jsonArray[1].toObject()["e"].toString() );
        jwk.insert( "kid", "qgis_dcs" );
        jwks.append( jwk );
        map.insert( "jwks", jwks );
    }

    QByteArray json = QJsonWrapper::toJson( QVariant( map ), &res, &errStr );
    qDebug() << json;
    QNetworkRequest registerRequest( regUrl );
    QgsSetRequestInitiatorClass( registerRequest, QStringLiteral( "QgsAuthOAuth2Edit" ) );
    registerRequest.setHeader( QNetworkRequest::ContentTypeHeader, QLatin1String( "application/json" ) );
    QNetworkReply *registerReply;
    // For testability: use GET if protocol is file://
    if ( regUrl.scheme() == QLatin1String( "file" ) )
        registerReply = QgsNetworkAccessManager::instance()->get( registerRequest );
    else
        registerReply = QgsNetworkAccessManager::instance()->post( registerRequest, json );
    mDownloading = true;
    connect( registerReply, &QNetworkReply::finished, this, &QgsAuthOAuth2Edit::registerReplyFinished, Qt::QueuedConnection );
    connect( registerReply, qgis::overload<QNetworkReply::NetworkError>::of( &QNetworkReply::error ), this, &QgsAuthOAuth2Edit::networkError, Qt::QueuedConnection );
}

void QgsAuthOAuth2Edit::getClientRegistration()
{
    if ( !mClientRegistrationEndpoint.isEmpty() )
    {
        clientRegistration( mClientRegistrationEndpoint );
    }
    else
    {
        mClientRegistrationEndpoint = mOAuthConfigCustom->regAuthUrl();
        this->clientRegistration(mClientRegistrationEndpoint);
    }
}

void QgsAuthOAuth2Edit::updatePredefinedLocationsTooltip()
{
  const QStringList dirs = QgsAuthOAuth2Config::configLocations( leDefinedDirPath->text() );
  QString locationList;
  QString locationListHtml;
  for ( const QString &dir : dirs )
  {
    if ( !locationList.isEmpty() )
      locationList += '\n';
    if ( locationListHtml.isEmpty() )
      locationListHtml = QStringLiteral( "<ul>" );
    locationList += QStringLiteral( "• %1" ).arg( dir );
    locationListHtml += QStringLiteral( "<li><a href=\"%1\">%2</a></li>" ).arg( QUrl::fromLocalFile( dir ).toString(), dir );
  }
  if ( !locationListHtml.isEmpty() )
    locationListHtml += QStringLiteral( "</ul>" );

  QString tip = QStringLiteral( "<p>" ) + tr( "Defined configurations are JSON-formatted files, with a single configuration per file. "
                "This allows configurations to be swapped out via filesystem tools without affecting user "
                "configurations. It is recommended to use the Configure tab’s export function, then edit the "
                "resulting file. See QGIS documentation for further details." ) + QStringLiteral( "</p><p>" ) +
                tr( "Configurations files can be placed in the directories:" ) + QStringLiteral( "</p>" ) + locationListHtml;
  pteDefinedDesc->setHtml( tip );

  lstwdgDefinedConfigs->setToolTip( tr( "Configuration files can be placed in the directories:\n\n%1" ).arg( locationList ) );
}

/***************************************************************************
    oqsstanagprovideroptions.h
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

#ifndef QGSSTANAGPROVIDEROPTIONS_H
#define QGSSTANAGPROVIDEROPTIONS_H

#include "../../core/qgsdataprovider.h"
#include "../wfs/qgsauthorizationsettings.h"
#include <QString>

struct StanagProviderOptions : QgsDataProvider::ProviderOptions {
  QgsAuthorizationSettings auth;
};

#endif // QGSSTANAGPROVIDEROPTIONS_H
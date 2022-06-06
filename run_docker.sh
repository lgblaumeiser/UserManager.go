#!/bin/sh
# SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
# SPDX-License-Identifier: MIT
docker run -d --name usermanager \
    -p 19749:8080 \
    -e "DBHOST=host.docker.internal"
    -e "DBPORT=5432"
    -e "DBUSER=postgres" \
    -e "DBPWD=postgres" \
    -e "DBNAME=usermanager" \
    --add-host=host.docker.internal:host-gateway \
    usermanager:1-pre
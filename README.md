# Surfshark Wireguard

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)

## About <a name = "about"></a>

A docker image for generating SurfShark-specific WireGurard tokens and making recurring token renewal.

## Getting Started <a name = "getting_started"></a>

Compose file for SurfShark Wireguard image with local storage:

```YAML
version: "3"
services:
  python:
    build: .
    image: redis_python_alpine:latest
    environment:
      # required: method used for data storage, it's either "File" or "Redis"
      - method=File

      # required: Username used in Surfshark credential/login page
      - username=<username>

      # required: Password used in 
      - password=<password>

      # Any field of "TZ database name" column of timezone wiki page
      # https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
      - timezone=<timezone>
    depends_on: 
      - redis
```

Compose file for SurfShark Wireguard image with Redis:

```YAML
version: "3"
services:
  redis:
    image: redis:alpine
    volumes:
      # for persistent storage of data
      - ./redis:/data
    command: ["/bin/sh", "-c", "redis-server --save 60 1 --loglevel warning"]
  python:
    build: .
    image: redis_python_alpine:latest
    environment:
      # required: method used for data storage, it's either "File" or "Redis"
      - method=Redis

      # Redis-specific config, it's only applicable for method=Redis
      # Redis-related connection config, be default, redis_host=redis AND redis_port=6379
      - redis_host=redis
      - redis_port=6379

      # required: Username used in Surfshark credential/login page
      - username=<username>

      # required: Password used in 
      - password=<password>

      # Any field of "TZ database name" column of timezone wiki page
      # https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
      - timezone=<timezone>
    depends_on: 
      - redis
```



TODO

## Prerequisites

TODO

## Installing

TODO

## Usage <a name = "usage"></a>

TODO

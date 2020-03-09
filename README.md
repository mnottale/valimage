# Valimage: an image validation server.

Valimage is an image validation server written in Rust.

## User workflow

Authenticated clients can have the 'user' or the 'reviewer' role.

Users can upload images and see their validation status. They can also delete
their images at any stage.

Reviewers can view all images, and either accept or decline those waiting for
review, as well as deleting any image.

## Storage

Two different storages are used: one for pending and declined images, and one for
validated images. Currently two storage backends are supported: filesystem and S3.

All access to un-validated images go through the server and are authenticated.

Access to validated images does not require authentication (the idea is to allow
users to share links to their images).

## Authentication

Only the demo mode is implemented now. It is expected that valimage will be
integrated in existing systems, so you'll have to implement your own authentication
module. A sample REST-delegating module will be implemented eventually.

## Requirements

  - A postgresql database. You need to create the database, user and table used by
this program yourself for now. See src/database.rs for the latest schema.
  - Write access to two directories, 'store/live' and 'store/pending', or to two
  S3 buckets (or any combination of the above).

## Features

  - Quota per user, settable as both total size and image count, as well as max upload size.
  - Restrict list of accepted mime-types (For security reasons it is advised to not allow SVG for now as SVG can contain javascript).
  - Cookie-based authentication using signed cookie for very lightweight session management.
  - 0-dependencies javascript interface.

## Configuration

The program loads 'config.yaml' at startup. Everything can be configured there.
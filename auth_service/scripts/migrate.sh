#!/bin/bash

flyway migrate -schemas=users -locations=filesystem:./migrations

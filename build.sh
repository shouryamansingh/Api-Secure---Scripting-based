#!/usr/bin/env bash
# Production build (used by Render): installs the backend, builds the React
# frontend, and places it in ./public where Flask serves it from.
# VITE_* environment variables must be set before this runs.
set -o errexit

pip install -r requirements.txt

cd frontend
npm ci
npm run build
cd ..

rm -rf public
cp -r frontend/dist public

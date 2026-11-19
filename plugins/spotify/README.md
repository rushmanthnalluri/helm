# Spotify Media Controller Plugin for Helm

Control playback, browse playlists, search tracks and podcasts via Spotify Web API using `spotipy`.

## Tools Provided
- `spotify_play`: Search and play a track by query or resume playback
- `spotify_pause`: Pause playback
- `spotify_now_playing`: Get information about the currently playing track

## Configuration
Requires Spotify API credentials set in your environment:
- `SPOTIPY_CLIENT_ID`
- `SPOTIPY_CLIENT_SECRET`
- `SPOTIPY_REDIRECT_URI` (default: http://localhost:8888/callback)
or:
- `SPOTIPY_AUTH_TOKEN`

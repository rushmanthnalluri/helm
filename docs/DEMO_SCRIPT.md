# Helm — Windows Desktop Assistant (Concept Storyboard)

**Duration:** About 60 seconds
**Status:** Concept only. This storyboard is not a live recording, a product acceptance result, or a performance report. The local dictation path is wired into the desktop app, but physical compatibility testing across Windows applications is pending.

## Storyboard

| Time | Visual | Narration / on-screen copy |
| --- | --- | --- |
| 0:00–0:08 | Windows desktop with a text editor and Helm source open. | “Helm is a Windows desktop assistant with local voice dictation and optional AI providers.” |
| 0:08–0:18 | Open the Omnibar and select an example result. Do not show a latency counter or claim a measured search size. | “Use the desktop shortcuts to reach search and assistant features.” |
| 0:18–0:30 | Show the proposed dictation flow as a clearly labeled example. If recording a real run, first validate it on the target Windows version and app. | “The dictation path uses local Whisper and Unicode keyboard input. Clipboard contents are not used by this path.” |
| 0:30–0:42 | Show an approval-flow diagram, not a simulated biometric success screen. Include both an enrolled-device approval and a denial when no device is enrolled. | “Approval depends on the route. Windows Hello is used on selected broker paths. Supervisor-protected actions also require signed evidence from an enrolled device.” |
| 0:42–0:52 | Show provider settings and a data-flow card: local transcription; configured local or cloud AI; connected integrations when invoked. | “Speech transcription is local by default. If you choose a cloud AI provider, its service receives the prompt and included context. Optional cloud speech fallback must be enabled separately.” |
| 0:52–1:00 | End card: “Source build available · No public installer yet.” Link to the source setup and packaging guide. | “Helm is under active development. A public signed installer is not available yet.” |

## Evidence required before publishing a product demo

- Record the workflow on supported Windows versions and actual target apps.
- Publish the tested app and OS matrix, plus dictation success and failure rates.
- Measure cold start, transcription, and insertion separately over a stated sample size.
- Show real approval behavior for both enrolled-device and no-device cases.
- Replace the source-only end card only after a signed release artifact is published and independently verifiable.

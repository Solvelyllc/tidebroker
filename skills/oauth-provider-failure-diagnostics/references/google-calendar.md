# Google Calendar provider recovery

Use this branch only when token refresh succeeds and the Calendar request returns HTTP 403 with the validated code `accessNotConfigured`.

1. Read `project_id` from the downloaded OAuth client configuration. Treat it as non-secret metadata and validate its shape before using it. Complete when one project identifier is resolved from the same client configuration used by the worker.

2. Open the Google Calendar API library page for that project:

   `https://console.cloud.google.com/apis/library/calendar-json.googleapis.com?project=<project_id>`

   Complete when the Calendar API is enabled for the diagnosed OAuth project.

3. Return to the shared procedure and re-run the original connector operation. Complete when the normal worker call succeeds.

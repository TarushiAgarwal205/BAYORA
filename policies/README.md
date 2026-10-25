Option A: Red Team may request explicitly approved security tests but must not read Blue Team artifacts. All other unapproved operations receive a default DENY from the policy decision endpoint.

`rules.json` contains the policy rules evaluated by `POST /policy/decide` and `POST /resource/read`. The first route records a decision only. The second route checks the decision before it calls the Blue service for the single `blue:synthetic-confidential` fixture. Roles are self-declared, so this is not user authentication.

The gateway does not call the Blue service on DENY. Blue also requires a shared service token on direct requests. This is a basic local demonstration, not general resource protection.

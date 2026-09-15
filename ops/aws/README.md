# AWS broker

The AWS adapter is deployable with the tracked systemd unit and startup loader:

1. Install Node 24, clone the repository at `/opt/deployseal`, and run `npm ci`
   in `server/` and `contracts/deployseal/`.
2. Create `/etc/deployseal/server.env` from `server.env.example`.
3. Put the required values in `/etc/deployseal/secrets` using the filenames
   referenced by `start.sh`.
4. Grant the instance role CloudFormation `ExecuteChangeSet`/`DescribeChangeSet`,
   CloudTrail `LookupEvents`, and KMS `Sign`/`Verify` for the configured resources.
5. Install `deployseal.service`, provision the TLS files, then enable the unit.

The CloudFormation change set must already exist and accept the
`DeploySealArtifactDigest` parameter. The instance role is the credential source;
the application does not read static AWS access keys.

# cloudtrail-today

`cloudtrail-today` is a tool for summarizing CloudTrail logs. To use, run with the `bucket` flag set to the name of the S3 bucket your CloudTrail logs are in:

    cloudtrail-today -bucket=my-cloudtrail-bucket

`cloudtrail-today` will download the log files and generate a summary report of all IAM subjects (e.g. IAM user or IAM role), the services they have used (e.g. EC2, S3), and the actions they performed (e.g. `ListBuckets`, `DeleteNetworkInterface`).

## cloudtrail-today.json

Since each run takes a while to download and process all of the logs, the summaries of days other than the current day are cached in a file named cloudtrail-today.json.

## Flags:

`region`: Default is `us-east-1`
`date`: Default is today.
`invalidate-cache`: Ignore/overwrite value in file.
`debug`: Flag to turn on additional logs.

    cloudtrail-today -bucket=my-cloudtrail-bucket -region=us-west-2 -date=2018/05/28 -invalidate-cache -debug


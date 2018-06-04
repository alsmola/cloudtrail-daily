# cloudtrail-daily

`cloudtrail-daily` is a Go command line tool for summarizing CloudTrail logs.

If your CloudTrail logs are in `s3://my-cloudtrail-bucket/`:

    cloudtrail-daily -account=1234567890 -bucket=my-cloudtrail-bucket

`cloudtrail-daily` will download the log files and generate a summary report of all IAM users and roles, the services used (e.g. `s3.amazonaws.com`), and the actions performed (e.g. `ListBuckets`).

## Example output

```
User: alsmola
    Service: s3.amazonaws.com
        Action: ListObjects
        Action: GetObject
    Service: sts.amazonaws.com
        Action: GetSessionToken
        Action: AssumeRole
Role: RedirectToIndex/us-east-1.RedirectToIndex
    Service: logs.amazonaws.com
        Action: CreateLogStream
```

## To build

    go build

## cloudtrail-daily.json

Since each run takes a while to download and process all of the logs, the summaries of days other than the current day are cached in a file named `cloudtrail-daily.json`.

## Other Flags

`region`: Default is `us-east-1`

`date`: Default is today.

`invalidate-cache`: Ignore/overwrite value in file.

`debug`: Flag to turn on additional logs.

### Flags example

    cloudtrail-daily -account=1234567890 -bucket=my-cloudtrail-bucket -region=us-west-2 -date=2018/05/28 -invalidate-cache -debug


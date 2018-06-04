package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/alsmola/cloudtrail-daily/models"
	"io/ioutil"
	"log"
	"time"
)

type RegionUsagesOutput map[string]models.RegionUsages

func jsonKey(bucket, region, date string) string {
	return fmt.Sprintf("%s/%s/%s", bucket, region, date)
}

func main() {
	var regionUsages models.RegionUsages
	regionUsagesOutput := RegionUsagesOutput{}

	accountPtr := flag.String("account", "", "The account of the CloudTrail logs")
	bucketPtr := flag.String("bucket", "", "The S3 bucket storing CloudTrail logs")
	regionPtr := flag.String("region", "us-east-1", "The CloudTrail logs region to view")
	datePtr := flag.String("date", "", "The CloudTrail logs date to view")
	debugPtr := flag.Bool("debug", false, "View debug logs")
	invalidateCachePtr := flag.Bool("invalidate-cache", false, "To invalidate cache for the region and day")
	flag.Parse()
	account := *accountPtr
	bucket := *bucketPtr
	region := *regionPtr
	date := *datePtr
	invalidateCache := *invalidateCachePtr

	if account == "" {
		log.Fatal(fmt.Errorf("No account provided. Pass the account with your CloudTrail logs using the -account flag (e.g. cloudtrail-daily -account=1234567890 -bucket=my-cloudtrail-bucket)."))
	}

	if bucket == "" {
		log.Fatal(fmt.Errorf("No bucket provided. Pass the S3 bucket with your CloudTrail logs using the -bucket flag (e.g. cloudtrail-daily -account=1234567890 -bucket=my-cloudtrail-bucket)."))
	}

	if !*debugPtr {
		// turn off logs
		log.SetFlags(0)
	}

	cloudtrailJson, err := ioutil.ReadFile("./cloudtrail-daily.json")
	if err != nil {
		log.Print("cloudtrail-daily.json not found, creating...")
		regionUsagesOutputJson, _ := json.Marshal(regionUsagesOutput)
		err = ioutil.WriteFile("cloudtrail-daily.json", regionUsagesOutputJson, 0644)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err = json.Unmarshal(cloudtrailJson, &regionUsagesOutput)
		if err != nil {
			log.Fatal(err)
		}
	}

	if date == "" {
		today := time.Now().Local().Format("2006/01/02")
		date = today
	} else if !invalidateCache {
		key := jsonKey(bucket, region, date)
		regionUsages = regionUsagesOutput[key]
		if regionUsages != nil {
			log.Print("Found in cloudtrail-daily.json: ", key)
		} else {
			log.Print("Not found in cloudtrail-daily.json: ", key)
		}
	}

	if regionUsages == nil {
		regionUsages, err = ParseS3Files(account, bucket, date, region)
		if err != nil {
			log.Fatal(err)
		}
		key := jsonKey(bucket, region, date)
		regionUsagesOutput[key] = regionUsages
		regionUsagesOutputJson, _ := json.Marshal(regionUsagesOutput)
		err = ioutil.WriteFile("cloudtrail-daily.json", regionUsagesOutputJson, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println(regionUsages.String())
}

package main

import (
	"encoding/csv"
	"fmt"
	"github.com/alsmola/cloudtrail-today/models"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"io"
	"log"
	"regexp"
	"strings"
)

func main() {
	regionUsages, err := parseS3File("azs-iam-activity-daily", "all", "2018/05/15")
	if err != nil {
		panic(err)
	}
	log.Print("Usages: " + regionUsages.String())
}

func parseS3File(bucket string, actionType string, date string) (models.RegionUsages, error) {
	sess := session.Must(session.NewSession())
	svc := s3.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})
	prefix := fmt.Sprintf("%s/%s", date, actionType)
	log.Printf("Looking at bucket s3://%s/%s...", bucket, prefix)
	objects, err := svc.ListObjects(&s3.ListObjectsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	if err != nil {
		return nil, err
	}

	key := ""
	for _, object := range objects.Contents {
		if strings.HasSuffix(*object.Key, ".csv") {
			key = *object.Key
		}
	}

	if key == "" {
		return nil, fmt.Errorf("Expected csv file in bucket")
	}

	log.Printf("Looking up file s3://%s/%s", bucket, key)

	out, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return nil, err
	}
	r := csv.NewReader(out.Body)
	_, err = r.Read()
	if err != nil {
		return nil, err
	}
	regionUsages := models.RegionUsages{}
	for {
		line, err := r.Read()
		if err == io.EOF {
			break
		}
		serviceStr := line[0]
		regionStr := line[1]
		actionStr := line[2]
		subjectStr := line[3]
		if _, ok := regionUsages[regionStr]; !ok {
			regionUsages[regionStr] = models.RegionUsage{Region: regionStr, Usages: map[string]models.Usage{}}
		}
		regionUsage := regionUsages[regionStr]
		usages := regionUsage.Usages

		subject, name, err := GetSubject(subjectStr)
		if err != nil {
			return nil, err
		}
		if _, ok := usages[name]; !ok {
			usages[name] = models.Usage{Subject: subject, Services: map[string]models.Service{}}
		}
		usage := usages[name]
		if _, ok := usage.Services[serviceStr]; !ok {
			usage.Services[serviceStr] = models.Service{Actions: map[string]models.Action{}}
		}
		service := usage.Services[serviceStr]

		if _, ok := service.Actions[actionStr]; !ok {
			service.Actions[actionStr] = models.Action{}
		}
	}
	return regionUsages, nil
}

func GetSubject(subjectStr string) (models.Subject, string, error) {
	s := models.Subject{}
	name := ""
	roleRegExp := `arn:aws:sts::(\d*):assumed-role\/(.*)`
	re1, _ := regexp.Compile(roleRegExp)
	result := re1.FindStringSubmatch(subjectStr)
	if len(result) > 0 {
		s.Role = &models.Role{
			Account: result[1],
			Name:    result[2],
		}
		name = fmt.Sprintf("role:%s", s.Role.Name)
	} else {
		userRegExp := `arn:aws:iam::(\d*):user\/(.*)`
		re2, _ := regexp.Compile(userRegExp)
		result = re2.FindStringSubmatch(subjectStr)
		if len(result) > 0 {
			s.User = &models.User{
				Account: result[1],
				Name:    result[2],
			}
			name = fmt.Sprintf("user:%s", s.User.Name)
		} else {
			return s, "", fmt.Errorf("No matching role/user pattern for subject: " + subjectStr)
		}
	}
	return s, name, nil
}

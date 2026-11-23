package b2

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Bucket struct {
	s3Client *s3.Client
	name     string
}

func New(keyId, applicationKey, region, name string) (Bucket, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(
		credentials.NewStaticCredentialsProvider(string(keyId), string(applicationKey), ""),
	), config.WithRegion(region))
	if err != nil {
		return Bucket{}, fmt.Errorf("error creating config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(fmt.Sprintf("https://s3.%s.backblazeb2.com", region))
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	return Bucket{
		s3Client: client,
		name:     name,
	}, nil
}

func (b Bucket) Get(key string) (io.Reader, error) {
	obj, err := b.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(b.name),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching %s/%s from B2: %w", b.name, key, err)
	}

	return obj.Body, nil
}

func (b Bucket) Put(key string, r io.Reader) error {
	hasher := md5.New()
	tmp, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return fmt.Errorf("error while creating temporary file: %w", err)
	}
	if _, err = io.Copy(io.MultiWriter(tmp, hasher), r); err != nil {
		return fmt.Errorf("error writing encrypted data to tmeporary file: %w", err)
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("error rewinding temporary file: %w", err)
	}

	_, err = b.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:     aws.String(b.name),
		Key:        aws.String(key),
		Body:       tmp,
		ContentMD5: aws.String(base64.StdEncoding.EncodeToString(hasher.Sum(nil))),
	})
	if err != nil {
		return fmt.Errorf("error writing %s/%s to B2: %w", b.name, key, err)
	}

	return nil
}

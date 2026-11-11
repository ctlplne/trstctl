// SPDX-License-Identifier: BUSL-1.1

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// A206-L2: a bucket that keeps versions (S3 Object Lock turns versioning on)
// keeps an object's data after a plain delete: the delete only adds a delete
// marker, so HEAD answers 404 while the version stays. A removal that must
// leave nothing behind lists the object's versions, deletes each by its ID,
// and lists again to confirm none is left.

// Version is one stored version of an object, or one of its delete markers.
// A bucket without versioning lists an object's single version as "null".
type Version struct {
	ID           string
	DeleteMarker bool
}

// Versioned is a store that can keep several versions of an object.
type Versioned interface {
	// Versions lists every version of the object and its delete markers.
	Versions(ctx context.Context, name string) ([]Version, error)
	// LockVersion reads one version's S3 Object Lock.
	LockVersion(ctx context.Context, name, version string) (LockState, error)
	// DeleteVersion deletes one version or delete marker for good.
	DeleteVersion(ctx context.Context, name, version string) error
}

var _ Versioned = (*S3)(nil)

// ErrVersionsUnsupported is a store that does not list object versions (it
// answers NotImplemented). Such a store keeps no versions, so a plain delete
// removes the data.
var ErrVersionsUnsupported = errors.New("objectstore: the store does not list object versions")

// maxObjectVersions bounds the versions one object may list. trstctl writes
// an object once (If-None-Match: *), so a key holds one version and whatever
// delete markers plain deletes left.
const maxObjectVersions = 1000

var errNoVersionID = errors.New("objectstore: a version ID is required")

// Versions lists every version of an object and its delete markers, exactly
// that key's and no other key's that shares its prefix.
func (s *S3) Versions(ctx context.Context, name string) ([]Version, error) {
	key, err := s.key(name)
	if err != nil {
		return nil, err
	}
	var versions []Version
	var keyMarker, versionMarker *string
	for {
		var page *s3.ListObjectVersionsOutput
		err := s.call(ctx, 0, func(ctx context.Context) error {
			out, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: awssdk.String(s.bucket), Prefix: awssdk.String(key), MaxKeys: awssdk.Int32(listPageSize),
				KeyMarker: keyMarker, VersionIdMarker: versionMarker,
			})
			if notImplemented(err) {
				return ErrVersionsUnsupported
			}
			page = out
			return classify(err, name)
		})
		if err != nil {
			return nil, err
		}
		// S3 lists keys in order, so once a longer key that shares the
		// prefix appears, every entry of this key has been listed.
		past := false
		for _, v := range page.Versions {
			if awssdk.ToString(v.Key) != key {
				past = true
				continue
			}
			versions = append(versions, Version{ID: awssdk.ToString(v.VersionId)})
		}
		for _, m := range page.DeleteMarkers {
			if awssdk.ToString(m.Key) != key {
				past = true
				continue
			}
			versions = append(versions, Version{ID: awssdk.ToString(m.VersionId), DeleteMarker: true})
		}
		if len(versions) > maxObjectVersions {
			return nil, fmt.Errorf("objectstore: %s has more than %d versions", name, maxObjectVersions)
		}
		if past || !awssdk.ToBool(page.IsTruncated) {
			return versions, nil
		}
		if awssdk.ToString(page.NextKeyMarker) == "" {
			return nil, fmt.Errorf("objectstore: the versions of %s were cut short without a marker to continue from", name)
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}

// DeleteVersion deletes one version of an object, or one delete marker, for
// good. A version already gone is not an error; the store refuses a version
// its S3 Object Lock protects.
func (s *S3) DeleteVersion(ctx context.Context, name, version string) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	if version == "" {
		return errNoVersionID
	}
	return s.call(ctx, 0, func(ctx context.Context) error {
		_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: awssdk.String(s.bucket), Key: awssdk.String(key), VersionId: awssdk.String(version),
		})
		if err = classify(err, name); errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
}

// notImplemented is a store answering that it does not implement a request.
func notImplemented(err error) bool {
	if err == nil {
		return false
	}
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "NotImplemented" {
		return true
	}
	var response *awshttp.ResponseError
	return errors.As(err, &response) && response.HTTPStatusCode() == http.StatusNotImplemented
}

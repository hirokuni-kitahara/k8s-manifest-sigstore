//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package kustomize

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/theupdateframework/go-tuf/encrypted"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const cosignPwdEnvKey = "COSIGN_PASSWORD"

// generate provenance data by checking kustomization.yaml and its sub resources
// all local files and remote repos are included in `materials` of a generated provenance
func GenerateProvenance(artifactName, digest, kustomizeBase string, startTime, finishTime time.Time, recipeCmd []string) (*intoto.Statement, error) {

	subjects := []intoto.Subject{}
	subjects = append(subjects, intoto.Subject{
		Name: artifactName,
		Digest: intotoprov02.DigestSet{
			"sha256": digest,
		},
	})

	materials, err := generateMaterialsFromKustomization(kustomizeBase)
	if err != nil {
		return nil, err
	}

	// TODO: set recipe command dynamically or somthing
	entryPoint := recipeCmd[0]
	invocation := intotoprov02.ProvenanceInvocation{
		ConfigSource: intotoprov02.ConfigSource{EntryPoint: entryPoint},
		Parameters:   recipeCmd[1:],
	}
	it := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: intotoprov02.PredicateSLSAProvenance,
			Subject:       subjects,
		},
		Predicate: intotoprov02.ProvenancePredicate{
			Metadata: &intotoprov02.ProvenanceMetadata{
				Reproducible:    true,
				BuildStartedOn:  &startTime,
				BuildFinishedOn: &finishTime,
			},

			Materials:  materials,
			Invocation: invocation,
		},
	}
	return it, nil
}

// generate a rekor entry data by signing a specified provenance with private key
// the output data contains a base64 encoded provenance and its signature.
// it can be used in `rekor-cli upload --artifact xxxxx`.
func GenerateAttestation(provPath, privKeyPath string) (*dsse.Envelope, error) {
	b, err := ioutil.ReadFile(provPath)
	if err != nil {
		return nil, err
	}
	ecdsaPriv, _ := ioutil.ReadFile(filepath.Clean(privKeyPath))
	pb, _ := pem.Decode(ecdsaPriv)
	pwd := os.Getenv(cosignPwdEnvKey) //GetPass(true)
	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}

	signer, err := dsse.NewEnvelopeSigner(&IntotoSigner{
		key: priv.(*ecdsa.PrivateKey),
	})
	if err != nil {
		return nil, err
	}

	envelope, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		return nil, err
	}

	// Now verify
	_, err = signer.Verify(envelope)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

// get a digest of artifact by checking artifact type
// when the artifact is local file --> sha256 file hash
//                   is OCI image --> image digest
func GetDigestOfArtifact(artifactPath string) (string, error) {
	var digest string
	var err error
	if FileExists(artifactPath) {
		// if file exists, then use hash of the file
		digest, err = Sha256Hash(artifactPath)
	} else {
		// otherwise, artifactPath should be an image ref
		digest, err = GetImageDigest(artifactPath)
	}
	return digest, err
}

// overwrite `subject` in provenance with a specified artifact
func OverwriteArtifactInProvenance(provPath, overwriteArtifact string) (string, error) {
	b, err := ioutil.ReadFile(provPath)
	if err != nil {
		return "", err
	}
	var prov *intoto.Statement
	err = json.Unmarshal(b, &prov)
	if err != nil {
		return "", err
	}
	digest, err := GetDigestOfArtifact(overwriteArtifact)
	if err != nil {
		return "", err
	}
	subj := intoto.Subject{
		Name: overwriteArtifact,
		Digest: intotoprov02.DigestSet{
			"sha256": digest,
		},
	}
	if len(prov.Subject) == 0 {
		prov.Subject = append(prov.Subject, subj)
	} else {
		prov.Subject[0] = subj
	}
	provBytes, _ := json.Marshal(prov)
	dir, err := ioutil.TempDir("", "newprov")
	if err != nil {
		return "", err
	}
	basename := filepath.Base(provPath)
	newProvPath := filepath.Join(dir, basename)
	err = ioutil.WriteFile(newProvPath, provBytes, 0644)
	if err != nil {
		return "", err
	}
	return newProvPath, nil
}

func ReconstructBuildEnvironment(baseDir, provPath, reconstructRootDir string) (string, error) {
	rootDirInRepo, err := GitExec(baseDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.Wrap(err, "failed to get root directory of repository")
	}
	baseAbsPath, err := filepath.Abs(baseDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to get absolute path of base dir")
	}
	rootDirInRepo = strings.TrimSuffix(rootDirInRepo, "\n")
	relativePath := strings.TrimPrefix(baseAbsPath, rootDirInRepo)

	err = copyDir(rootDirInRepo, reconstructRootDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to copy kustomize base dir to the temporary dir")
	}

	b, err := ioutil.ReadFile(provPath)
	if err != nil {
		return "", errors.Wrap(err, "failed to read provenance data")
	}
	var prov *intoto.Statement
	err = json.Unmarshal(b, &prov)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal provenance data into in-toto.Statement")
	}
	predicateBytes, _ := json.Marshal(prov.Predicate)
	var predicate intotoprov02.ProvenancePredicate
	err = json.Unmarshal(predicateBytes, &predicate)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal predicate into intotoprov02.ProvenancePredicate")
	}
	provMap := map[string]intotoprov02.DigestSet{}
	for _, material := range predicate.Materials {
		uri := material.URI
		digest := material.Digest
		provMap[uri] = digest
	}

	reconstructBaseDir := filepath.Join(reconstructRootDir, relativePath)
	// need resolve symlink if any because git command do this and it possibly causes path inconsistency later
	reconstructBaseDir, err = filepath.EvalSymlinks(reconstructBaseDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to resolve symlink")
	}
	err = overwriteCommitIDInKustomizeBaseDir(reconstructBaseDir, provMap)
	if err != nil {
		return "", errors.Wrap(err, "failed to overwrite kustomize commit IDs")
	}
	return reconstructBaseDir, nil
}

func overwriteCommitIDInKustomizeBaseDir(baseDir string, provMap map[string]intotoprov02.DigestSet) error {
	repoURL, currentRevision, _, _, err := checkRepoInfoOfKustomizeBase(baseDir)
	if err != nil {
		return errors.Wrap(err, "failed to get repo info of base dir")
	}
	if digest, ok := provMap[repoURL]; ok {
		commitInProv := digest["commit"]
		if currentRevision != commitInProv {
			_, err = GitExec(baseDir, "checkout", commitInProv)
			if err != nil {
				return errors.Wrap(err, "failed to checkout a commit in the base repo")
			}
		}
	}
	kustFullPath := filepath.Join(baseDir, "kustomization.yaml")

	k, err := loadKustomizationYAML(kustFullPath)
	if err != nil {
		return errors.Wrap(err, "failed to read kustomization.yaml in base repo")
	}
	for i := range k.Resources {
		resourceURL := k.Resources[i]
		parts := strings.Split(resourceURL, "/")
		subParts := []string{}
		gitJ := -1
		for j := range parts {
			if parts[j] == "github.com" {
				gitJ = j
			}
			if j <= gitJ+2 {
				subParts = append(subParts, parts[j])
			}
		}
		gitRepoSubStr := strings.Join(subParts, "/")
		for repo, digest := range provMap {
			if strings.Contains(repo, gitRepoSubStr) {
				re := regexp.MustCompile(`\?ref=.*`)
				newCommitRef := fmt.Sprintf("?ref=%s", digest["commit"])
				resourceURL = string(re.ReplaceAll([]byte(resourceURL), []byte(newCommitRef)))
				break
			}
		}
		k.Resources[i] = resourceURL
	}

	kustomizeConfigBytes, _ := yaml.Marshal(k)
	err = ioutil.WriteFile(kustFullPath, kustomizeConfigBytes, 0755)
	if err != nil {
		return errors.Wrap(err, "failed to write kustomization.yaml")
	}
	return nil
}

func generateMaterialsFromKustomization(kustomizeBase string) ([]intotoprov02.ProvenanceMaterial, error) {
	var resources []*KustomizationResource
	var err error
	repoURL, repoRevision, _, kustPath, err := checkRepoInfoOfKustomizeBase(kustomizeBase)
	if err == nil {
		// a repository in local filesystem
		resources, err = LoadKustomization(kustPath, "", repoURL, repoRevision, true)
	} else {
		// pure kustomization.yaml which is not in repository
		resources, err = LoadKustomization(kustomizeBase, "", "", "", false)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to load kustomization to generate manifest")
	}
	materials := []intotoprov02.ProvenanceMaterial{}
	for _, r := range resources {
		m := resourceToMaterial(r)
		if m == nil {
			continue
		}
		materials = append(materials, *m)
	}
	return materials, nil
}

func checkRepoInfoOfKustomizeBase(kustomizeBase string) (string, string, string, string, error) {
	url, err := GitExec(kustomizeBase, "config", "--get", "remote.origin.url")
	if err != nil {
		return "", "", "", "", errors.Wrap(err, "failed to get remote.origin.url")
	}
	url = strings.TrimSuffix(url, "\n")
	revision, err := GitExec(kustomizeBase, "rev-parse", "HEAD")
	if err != nil {
		return "", "", "", "", errors.Wrap(err, "failed to get revision HEAD")
	}
	revision = strings.TrimSuffix(revision, "\n")
	absKustBase, err := filepath.Abs(kustomizeBase)
	if err != nil {
		return "", "", "", "", errors.Wrap(err, "failed to get absolute path of kustomize base dir")
	}
	rootDirInRepo, err := GitExec(kustomizeBase, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", "", "", errors.Wrap(err, "failed to get root directory of repository")
	}
	rootDirInRepo = strings.TrimSuffix(rootDirInRepo, "\n")
	relativePath := strings.TrimPrefix(absKustBase, rootDirInRepo)
	relativePath = strings.TrimPrefix(relativePath, "/")
	return url, revision, rootDirInRepo, relativePath, nil
}

func resourceToMaterial(kr *KustomizationResource) *intotoprov02.ProvenanceMaterial {
	if kr.File == nil && kr.GitRepo == nil {
		return nil
	} else if kr.File != nil {
		m := &intotoprov02.ProvenanceMaterial{
			URI: kr.File.Name,
			Digest: intotoprov02.DigestSet{
				"hash": kr.File.Hash,
			},
		}
		return m
	} else if kr.GitRepo != nil {
		m := &intotoprov02.ProvenanceMaterial{
			URI: kr.GitRepo.URL,
			Digest: intotoprov02.DigestSet{
				"commit":   kr.GitRepo.CommitID,
				"revision": kr.GitRepo.Revision,
				"path":     kr.GitRepo.Path,
			},
		}
		return m
	}
	return nil
}

// returns image digest
func GetImageDigest(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	hash, err := img.Digest()
	if err != nil {
		return "", err
	}
	hashValue := strings.TrimPrefix(hash.String(), "sha256:")
	return hashValue, nil
}

type IntotoSigner struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// sign a provenance data
func (it *IntotoSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	sig, err := it.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// sverify a provenance data and its signature
func (it *IntotoSigner) Verify(data, sig []byte) error {
	h := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(&it.key.PublicKey, h[:], sig)
	if ok {
		return nil
	}
	return errors.New("invalid signature")
}

func (es *IntotoSigner) KeyID() (string, error) {
	return es.keyID, nil
}

func (es *IntotoSigner) Public() crypto.PublicKey {
	return es.key.Public()
}

// copy an entire directory recursively
func copyDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if srcinfo.IsDir() {
		if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
			return err
		}

		if fds, err = ioutil.ReadDir(src); err != nil {
			return err
		}
		for _, fd := range fds {
			srcfp := path.Join(src, fd.Name())
			dstfp := path.Join(dst, fd.Name())

			if fd.IsDir() {
				if err = copyDir(srcfp, dstfp); err != nil {
					return err
				}
			} else {
				if err = copyFile(srcfp, dstfp); err != nil {
					return err
				}
			}
		}
	} else {
		if err = copyFile(src, dst); err != nil {
			return err
		}
	}

	return nil
}

// copy a single file
func copyFile(src string, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}

	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, input, fi.Mode())
	if err != nil {
		return err
	}
	return nil
}

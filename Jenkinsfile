// Jenkinsfile for building the GLauth image via plain `docker build` + `docker push`,
// targeting Aliyun ACR.
//
// Uses the agent's docker daemon directly. Registry credentials are written to the
// agent's ~/.docker/config.json via `docker login`, so the build and push need no
// buildx/buildctl plugin or standalone buildkitd container.
//
// Required Jenkins credential (usernamePassword):
//   - ALIYUN_ACR_MASS_LOGIN_PASSWORD  -> Aliyun ACR (maas-registry.cn-shanghai.cr.aliyuncs.com) login
//
// Tag is auto-generated: <yyyyMMdd-HHmm>-<shortCommit>, e.g. 20260903-1430-a1b2c3d.
// Override it with the IMAGE_TAG build parameter if needed.

pipeline {
    agent { label 'agent-hk-1' }

    environment {
        TARGET_REGISTRY = 'maas-registry-vpc.cn-shanghai.cr.aliyuncs.com'
        IMAGE_REPO      = 'ack/glauth'
        // v2/docker/Dockerfile builds from the v2 module root (COPY go.mod go.sum ./).
        CONTEXT_DIR     = 'v2'
        DOCKERFILE      = 'docker/Dockerfile'
    }

    parameters {
        string(
            name: 'IMAGE_TAG',
            defaultValue: '',
            description: 'Push tag. Empty = auto-generate <yyyyMMdd-HHmm>-<shortCommit> (e.g. 20260903-1430-a1b2c3d)'
        )
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    def shortCommit = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    def timestamp   = sh(script: 'date -u +%Y%m%d-%H%M', returnStdout: true).trim()
                    def tag = params.IMAGE_TAG?.trim() ?: "${timestamp}-${shortCommit}"
                    env.IMAGE_TAG = tag
                    env.IMAGE = "${env.TARGET_REGISTRY}/${env.IMAGE_REPO}:${tag}"

                    echo """
=========================================
Build GLauth Image
=========================================
Image:   ${env.IMAGE}
Commit:  ${shortCommit}
Context: ${env.CONTEXT_DIR} (${env.DOCKERFILE})
"""
                    // Verify the Dockerfile exists in the workspace.
                    sh '''
                        if [ ! -f ${CONTEXT_DIR}/${DOCKERFILE} ]; then
                            echo "[ERROR] Dockerfile not found: ${CONTEXT_DIR}/${DOCKERFILE}"
                            exit 1
                        fi
                        echo "[OK] Dockerfile found"
                    '''
                }
            }
        }

        stage('Build & Push') {
            steps {
                script {
                    // Embed the short commit as an OCI image label for traceability.
                    env.GIT_COMMIT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()

                    sh '''
                        set -euo pipefail

                        cd "${CONTEXT_DIR}"

                        echo "Building ${IMAGE} ..."
                        docker build \\
                            --label org.opencontainers.image.revision=${GIT_COMMIT} \\
                            --label org.opencontainers.image.version=${IMAGE_TAG} \\
                            -t "${IMAGE}" \\
                            -f "${DOCKERFILE}" \\
                            .

                        echo "Pushing ${IMAGE} ..."
                        docker push "${IMAGE}"

                        echo "Image pushed: ${IMAGE}"
                    '''
                }
            }
        }

        stage('Verify') {
            steps {
                sh '''
                    echo "[verify] Verifying pushed manifest ..."
                    docker manifest inspect ${IMAGE} >/dev/null \
                        && echo "[OK] Manifest verified: ${IMAGE}" \
                        || { echo "[ERROR] Manifest inspect failed for ${IMAGE}"; exit 1; }

                    echo ""
                    echo "Image details:"
                    docker manifest inspect ${IMAGE} \
                        | grep -E '"(architecture|os|mediaType|digest)"' || true
                '''
            }
        }
    }

    post {
        success {
            echo """
=============================================
  GLauth Image Built & Pushed
=============================================
Image:  ${env.IMAGE}
Commit: ${env.GIT_COMMIT}

Reference in a chart:
  image:
    repository: ${env.TARGET_REGISTRY}/${env.IMAGE_REPO}
    tag: ${env.IMAGE_TAG}
"""
        }
        failure {
            echo """
=============================================
  GLauth Image Build Failed
=============================================
Troubleshooting:
  1. Verify the ALIYUN_ACR_MASS_LOGIN_PASSWORD Jenkins credential exists and is valid
  2. Confirm the agent (agent-hk-1) has docker and network access to proxy.golang.org
     and gcr.io/distroless (the Dockerfile pulls Go modules and the distroless base)
  3. Review the build output above for the failing layer
"""
        }
    }
}

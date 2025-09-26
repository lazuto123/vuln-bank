pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Secret Scanning') {
            steps {
                sh '''
                echo "=== Running TruffleHog Secret Scanning (Remote Repo)==="
                docker run --rm trufflesecurity/trufflehog:latest \
                git https://github.com/lazuto123/vuln-bank --json > trufflehog_report.json || true
                echo "=== Scan finished. Report saved to trufflehog_report.json ==="
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trufflehog_report.json', allowEmptyArchive: true
                }
                failure {
                    echo "Secret scanning failed."
                }
            }
        }

        stage('SCA Snyk Test') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_TOKEN --entrypoint='
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Preparing CI requirements (patched install) ==="
                      cp requirements.txt requirements.ci.txt
                      sed -i 's/psycopg2-binary==2.9.9/psycopg2-binary==2.9.10/g' requirements.ci.txt
        
                      echo "=== Installing dependencies from requirements.ci.txt ==="
                      pip install --no-cache-dir -r requirements.ci.txt || true
        
                      echo "=== Running Snyk SCA Test against original requirements.txt ==="
                      snyk test --file=requirements.txt --package-manager=pip --json > snyk-scan-report.json || true
        
                      cat snyk-scan-report.json
                      echo "=== Snyk scan finished. Report saved to snyk-scan-report.json ==="
                    '''
                }
                archiveArtifacts artifacts: 'snyk-scan-report.json'
            }
        }

        stage('SAST Snyk Code') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_TOKEN --entrypoint='
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running Snyk SAST (Code Analysis) ==="
                      snyk code test --json > snyk-sast-report.json || true
        
                      cat snyk-sast-report.json
                      echo "=== Snyk SAST scan finished. Report saved to snyk-sast-report.json ==="
                    '''
                }
                archiveArtifacts artifacts: 'snyk-sast-report.json'
            }
        }

        stage('Misconfiguration Scanning (Dockerfile & compose)') {
            agent any
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      set -euo pipefail || true
                      echo "=== Misconfiguration scan: hadolint (Dockerfile) & kics (docker-compose.yml) ==="
        
                      # Hadolint for Dockerfile
                      if [ -f Dockerfile ]; then
                        echo "[hadolint] Dockerfile found — running hadolint..."
                        docker run --rm -v "$PWD":/data hadolint/hadolint:latest hadolint /data/Dockerfile -f json > hadolint-report.json || true
                        echo "[hadolint] report written to hadolint-report.json"
                      else
                        echo '[hadolint] Dockerfile not found, creating placeholder report'
                        echo '{"ok": false, "error": "Dockerfile not found"}' > hadolint-report.json
                      fi
        
                      # KICS for docker-compose.yml
                      if [ -f docker-compose.yml ]; then
                        echo "[kics] docker-compose.yml found — running KICS..."
                        # output-path will contain .json files; run as temporary directory 'kics-report'
                        rm -rf kics-report || true
                        docker run --rm -v "$PWD":/workspace checkmarx/kics:latest scan --path /workspace/docker-compose.yml --output-path /workspace/kics-report --report-formats json || true
        
                        # Normalize KICS output into single JSON file for downstream consumption
                        if [ -d kics-report ]; then
                          # concatenate all json outputs (if multiple) into one array-ish file (simple concat)
                          cat kics-report/*.json > kics-report.json 2>/dev/null || echo '{"ok": false, "error": "KICS produced no JSON output"}' > kics-report.json
                          echo "[kics] report written to kics-report.json"
                        else
                          echo '[kics] KICS did not produce output directory, creating placeholder report'
                          echo '{"ok": false, "error": "KICS scan failed or produced no output"}' > kics-report.json
                        fi
                      else
                        echo '[kics] docker-compose.yml not found, creating placeholder report'
                        echo '{"ok": false, "error": "docker-compose.yml not found"}' > kics-report.json
                      fi
        
                      echo "=== Misconfiguration scan finished ==="
                      echo "---- hadolint report ----"
                      cat hadolint-report.json || true
                      echo "---- kics report ----"
                      cat kics-report.json || true
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'hadolint-report.json,kics-report.json', allowEmptyArchive: true
                }
            }
        }

        
        stage('Deploy') {
            steps {
                sshagent(['DeploymentSSHKey']) {
                    sh '''
                        ssh -o StrictHostKeyChecking=no deployment@192.168.0.115 "
                          cd ~/vuln-bank || git clone -b main https://github.com/lazuto123/vuln-bank ~/vuln-bank
                          cd ~/vuln-bank && git pull origin main
                          docker-compose down || true
                          docker-compose up -d --build
                        "
                    '''
                }
            }
        }
    }
}

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
                    script {
                        if (fileExists('trufflehog_report.json')) {
                            def secrets = readJSON file: 'trufflehog_report.json'
                            if (secrets && secrets.size() > 0) {
                                emailext(
                                    subject: "Secret ditemukan di pipeline vuln-bank",
                                    body: """Halo Ilham,

Ditemukan ${secrets.size()} secret di hasil TruffleHog.

Silakan cek artifact trufflehog_report.json di Jenkins untuk detail.
""",
                                    to: "brigaup987@gmail.com"
                                )
                            }
                        }
                    }
                }
            }
        }

        stage('SCA Snyk Test') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args "-u root --network host --env SNYK_TOKEN=${env.SNYK_TOKEN} --entrypoint= -v ${env.WORKSPACE}:/workspace"
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running Snyk SCA Test ==="
                      snyk test --file=requirements.txt --package-manager=pip --json > /workspace/snyk-scan-report.json || true
                    '''
                }
                sh "cp /workspace/snyk-scan-report.json snyk-scan-report.json || true"
                archiveArtifacts artifacts: 'snyk-scan-report.json'
            }
            post {
                always {
                    script {
                        if (fileExists('snyk-scan-report.json')) {
                            def snyk = readJSON file: 'snyk-scan-report.json'
                            def vulns = snyk?.vulnerabilities ?: []
                            def highVulns = vulns.findAll { it.severity?.toLowerCase() in ["high","critical"] }
                            if (highVulns.size() > 0) {
                                emailext(
                                    subject: "Snyk SCA menemukan High/Critical vulnerability",
                                    body: """Halo Ilham,

Ditemukan ${highVulns.size()} High/Critical vulnerability di Snyk SCA.

Silakan cek artifact snyk-scan-report.json di Jenkins untuk detail.
""",
                                    to: "brigaup987@gmail.com"
                                )
                            }
                        }
                    }
                }
            }
        }

        stage('SAST Snyk Code') {
            agent {
                docker {
                    image 'snyk/snyk:python'
                    args "-u root --network host --env SNYK_TOKEN=${env.SNYK_TOKEN} --entrypoint= -v ${env.WORKSPACE}:/workspace"
                }
            }
            environment {
                SNYK_TOKEN = credentials('SnykToken')
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running Snyk SAST (Code Analysis) ==="
                      snyk code test --json > /workspace/snyk-sast-report.json || true
                    '''
                }
                sh "cp /workspace/snyk-sast-report.json snyk-sast-report.json || true"
                archiveArtifacts artifacts: 'snyk-sast-report.json'
            }
            post {
                always {
                    script {
                        if (fileExists('snyk-sast-report.json')) {
                            def sast = readJSON file: 'snyk-sast-report.json'
                            def results = sast?.runs?.collectMany { it.results } ?: []
                            def highIssues = results.findAll { it.level?.toLowerCase() == "error" }
                            if (highIssues.size() > 0) {
                                emailext(
                                    subject: "Snyk SAST menemukan High/Critical issue",
                                    body: """Halo Ilham,

Ditemukan ${highIssues.size()} High/Critical issue di Snyk SAST.

Silakan cek artifact snyk-sast-report.json di Jenkins untuk detail.
""",
                                    to: "brigaup987@gmail.com"
                                )
                            }
                        }
                    }
                }
            }
        }

        stage('Misconfiguration Scanning') {
            steps {
                sh '''
                echo "=== Running Checkov for Dockerfile ==="
                docker run --rm -v $(pwd):/src bridgecrew/checkov \
                    --directory /src --framework dockerfile \
                    --output json --output-file-path /src/checkov_report.json || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: '**/checkov_report*', allowEmptyArchive: true
                }
            }
        }

        stage('OS Hardening') {
            agent {
                docker {
                    image 'python:3.9-bullseye'
                    args '-u root --network host --entrypoint='
                }
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'DeploymentUserCred', 
                                                  usernameVariable: 'DEPLOY_USER', 
                                                  passwordVariable: 'DEPLOY_PASS')]) {
                    sh '''
                    echo "=== Installing Ansible ==="
                    pip3 install ansible
        
                    echo "=== Preparing inventory for remote server ==="
                    cat > inventory.ini <<EOL
        [ubuntuServer]
        192.168.0.115 ansible_user=${DEPLOY_USER} ansible_password=${DEPLOY_PASS} ansible_become_pass=${DEPLOY_PASS}
        EOL
        
                    echo "=== Preparing Ansible Playbook for OS Hardening ==="
                    cat > hardening.yml <<EOL
        ---
        - name: Playbook to harden Ubuntu OS
          hosts: ubuntuServer
          become: yes
          roles:
            - dev-sec.os-hardening
        EOL
        
                    echo "=== Installing required roles and collections ==="
                    ansible-galaxy collection install community.general
                    ansible-galaxy install dev-sec.os-hardening
        
                    echo "=== Running Ansible Playbook ==="
                    ansible-playbook -i inventory.ini hardening.yml -vvv
                    '''
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

        stage('DAST OWASP ZAP') {
            agent {
                docker {
                    image 'ghcr.io/zaproxy/zaproxy:stable'
                    args "-u root --network host -v /var/run/docker.sock:/var/run/docker.sock --entrypoint= -v ${env.WORKSPACE}:/zap/wrk/:rw"
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running OWASP ZAP Baseline Scan ==="
                      zap-baseline.py -t http://192.168.0.115:5000 \
                        -r /zap/wrk/zapbaseline.html \
                        -x /zap/wrk/zapbaseline.xml || true
                    '''
                }
                sh "cp /zap/wrk/zapbaseline.html zapbaseline.html || true"
                sh "cp /zap/wrk/zapbaseline.xml zapbaseline.xml || true"
                archiveArtifacts artifacts: 'zapbaseline.html'
                archiveArtifacts artifacts: 'zapbaseline.xml'
            }
            post {
                always {
                    script {
                        if (fileExists('zapbaseline.xml')) {
                            def highCount = sh(
                                script: "grep -c '<riskcode>[34]</riskcode>' zapbaseline.xml || true",
                                returnStdout: true
                            ).trim()
        
                            if (highCount.isInteger() && highCount.toInteger() > 0) {
                                emailext(
                                    subject: "OWASP ZAP menemukan High/Critical finding",
                                    body: """Halo Ilham,
        
        Ditemukan ${highCount} High/Critical finding di OWASP ZAP.
        
        Silakan cek artifact zapbaseline.xml/html di Jenkins untuk detail.
        """,
                                    to: "brigaup987@gmail.com"
                                )
                            }
                        }
                    }
        
                    withCredentials([string(credentialsId: 'DefectDojoAPIToken', variable: 'DD_API_TOKEN')]) {
                        sh '''
                        echo "=== Uploading results to DefectDojo ==="
                        DD_HOST="192.168.0.114"
                        DD_PORT="8081"
                        DD_URL="http://${DD_HOST}:${DD_PORT}/api/v2/import-scan/"
        
                        # TruffleHog (Secret Scanning)
                        if [ -f trufflehog_report.json ]; then
                          echo "Uploading trufflehog_report.json..."
                          curl -sS -X POST "$DD_URL" \
                            -H "Authorization: Token $DD_API_TOKEN" \
                            -F "scan_type=Trufflehog Scan" \
                            -F "file=@trufflehog_report.json" \
                            -F "engagement=1" || true
                        fi
        
                        # Snyk SCA
                        if [ -f snyk-scan-report.json ]; then
                          echo "Uploading snyk-scan-report.json..."
                          curl -sS -X POST "$DD_URL" \
                            -H "Authorization: Token $DD_API_TOKEN" \
                            -F "scan_type=Snyk Scan" \
                            -F "file=@snyk-scan-report.json" \
                            -F "engagement=1" || true
                        fi
        
                        # Snyk SAST (Code)
                        if [ -f snyk-sast-report.json ]; then
                          echo "Uploading snyk-sast-report.json..."
                          curl -sS -X POST "$DD_URL" \
                            -H "Authorization: Token $DD_API_TOKEN" \
                            -F "scan_type=Snyk Code Scan" \
                            -F "file=@snyk-sast-report.json" \
                            -F "engagement=1" || true
                        fi
        
                        # OWASP ZAP (DAST)
                        if [ -f zapbaseline.xml ]; then
                          echo "Uploading zapbaseline.xml..."
                          curl -sS -X POST "$DD_URL" \
                            -H "Authorization: Token $DD_API_TOKEN" \
                            -F "scan_type=ZAP Scan" \
                            -F "file=@zapbaseline.xml" \
                            -F "engagement=1" || true
                        fi
        
                        echo "=== Upload to DefectDojo finished ==="
                        '''
                    }
                }
            }
        }


        
    }
}

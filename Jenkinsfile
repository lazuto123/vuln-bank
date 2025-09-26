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
                    args '-u root --network host -v /var/run/docker.sock:/var/run/docker.sock --entrypoint= -v ./zap/wrk/:/zap/wrk/:rw'
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh '''
                      echo "=== Running OWASP ZAP Baseline Scan ==="
                      zap-baseline.py -t http://192.168.0.115:5000 -r zapbaseline.html -x zapbaseline.xml || true
                      echo "=== ZAP scan finished. Reports saved to zapbaseline.html and zapbaseline.xml ==="
                    '''
                }
                sh 'cp /zap/wrk/zapbaseline.html ./zapbaseline.html || true'
                sh 'cp /zap/wrk/zapbaseline.xml ./zapbaseline.xml || true'
                archiveArtifacts artifacts: 'zapbaseline.html'
                archiveArtifacts artifacts: 'zapbaseline.xml'
            }
        }

        stage('Notify') {
            steps {
                script {
                    def sendMail = false
                    def reportContent = ""
        
                    // === TruffleHog Secret Scanning ===
                    if (fileExists('trufflehog_report.json')) {
                        def secrets = readJSON file: 'trufflehog_report.json'
                        if (secrets && secrets.size() > 0) {
                            sendMail = true
                            reportContent += "Secrets ditemukan di TruffleHog!\n"
                        }
                    }
        
                    // === Snyk SCA ===
                    if (fileExists('snyk-scan-report.json')) {
                        try {
                            def snyk = readJSON file: 'snyk-scan-report.json'
                            def vulns = snyk?.vulnerabilities ?: []
                            echo "DEBUG SCA - total vulnerabilities: ${vulns.size()}"
                            def highVulns = vulns.findAll { it.severity?.toLowerCase() in ["high","critical"] }
                            echo "DEBUG SCA - High/Critical: ${highVulns.size()}"
                            if (highVulns.size() > 0) {
                                sendMail = true
                                reportContent += "${highVulns.size()} High/Critical vulnerability dari Snyk SCA!\n"
                            }
                        } catch (err) {
                            echo "ERROR parsing snyk-scan-report.json: ${err}"
                            sh "cat snyk-scan-report.json"
                        }
                    }
                            
                    // === Snyk SAST ===
                    if (fileExists('snyk-sast-report.json')) {
                        try {
                            def sast = readJSON file: 'snyk-sast-report.json'
                            def results = sast?.runs?.collectMany { it.results } ?: []
                            echo "DEBUG SAST - total results: ${results.size()}"
                            def highIssues = results.findAll { it.level?.toLowerCase() == "error" }
                            echo "DEBUG SAST - High/Critical: ${highIssues.size()}"
                            if (highIssues.size() > 0) {
                                sendMail = true
                                reportContent += "${highIssues.size()} High/Critical issue dari Snyk SAST!\n"
                            }
                        } catch (err) {
                            echo "ERROR parsing snyk-sast-report.json: ${err}"
                            sh "cat snyk-sast-report.json"
                        }
                    }
        
                    // === ZAP DAST ===
                    if (fileExists('zapbaseline.xml')) {
                        try {
                            def zapXml = new XmlSlurper().parse(new File("zapbaseline.xml"))
                            def allAlerts = zapXml.site.alerts.alertitem
                            echo "DEBUG ZAP - total alertitem: ${allAlerts.size()}"
                            def highFindings = allAlerts.findAll { it.riskcode.text() in ["3","4"] }
                            echo "DEBUG ZAP - High/Critical: ${highFindings.size()}"
                            if (highFindings.size() > 0) {
                                sendMail = true
                                reportContent += "${highFindings.size()} High/Critical finding dari OWASP ZAP!\n"
                            }
                        } catch (err) {
                            echo "ERROR parsing zapbaseline.xml: ${err}"
                            sh "cat zapbaseline.xml"
                        }
                    }
        
                    // === Kirim Email kalau ada temuan ===
                    if (sendMail) {
                        emailext(
                            subject: "Security Alerts di Pipeline - vuln-bank",
                            body: """Halo Ilham,
        
        Ditemukan masalah security pada pipeline vuln-bank:
        
        ${reportContent}
        
        Silakan cek artifact hasil scan (JSON/XML/HTML) di Jenkins untuk detail lebih lanjut.
        
        """,
                            to: "brigaup987@gmail.com"
                        )
                    } else {
                        echo "Tidak ada High/Critical findings, email tidak dikirim."
                    }
                }
            }
        }

    }
}

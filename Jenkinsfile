pipeline {
    agent any

    stages {
		stage('Secret Scanning') {
			agent {
				docker {
					image 'trufflesecurity/trufflehog:latest'
					args '--entrypoint'
				}
			}
			steps{
				catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE'){
					sh 'trufflehog filesystem --exclude-paths trufflehog-excluded-paths.txt --fail --json --no update > trufflehog-scan-result.json'
				}
				sh 'cat trufflehog-scan-result.json'
				archiveArtifacts artifacts: 'trufflehog-scan-result.json'
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

// CI de segsoft-motorpython en el Jenkins de p2tools (pi2tools.icesi.edu.co/jenkins).
// Equivale a .github/workflows/validate-engine.yml: valida que el motor cumpla los
// umbrales de precisión y cobertura de validation-thresholds.yml y publica
// validation-report.json y validation-report.md como artefactos del build.
//
// Requiere en Jenkins: los plugins Pipeline, Docker Pipeline y JUnit, y un agente con Docker.
pipeline {
    agent {
        docker {
            image 'python:3.11-slim'
            reuseNode true
        }
    }

    options {
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        CI = 'true'
        // El usuario del agente no puede instalar en el Python del sistema ni tiene HOME escribible.
        PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
    }

    stages {
        stage('Dependencias') {
            steps {
                sh '''
                    python -m venv .venv
                    .venv/bin/pip install --quiet --upgrade pip
                    .venv/bin/pip install --quiet ".[dev]"
                '''
            }
        }

        stage('Validación de precisión y cobertura') {
            steps {
                sh '.venv/bin/pytest tests/validation/ -v --junitxml=reports/validation.xml'
            }
        }
    }

    post {
        always {
            junit testResults: 'reports/validation.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'reports/validation-report.*', allowEmptyArchive: true
        }
    }
}

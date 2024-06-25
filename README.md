# EBDS Backend

## Getting started

You can get started with EBDS with our local or Docker quickstart.

## Install

```
pip install -r requirements.txt
```

## Migrations

```
alembic upgrade head
```
## Set up your Environment variable

```
touch .env
```

Find the .sample_env from the structure. Copy the contents and paste it in .env file. Replace the dummy values with your
actual account credentials.

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing(SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

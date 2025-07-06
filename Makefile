install:
	pip install -r requirements.txt

lint:
	flake8 .

format:
	black .

test:
	pytest

docker-build:
	docker build -t aws-kms-app .

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down 
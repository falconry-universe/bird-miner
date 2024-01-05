run:
	cd src && flask run --port 5000 --reload

build:
	docker build -t bird-miner .

run-docker:
	docker run --env_file=.env -p 5000:5000 bird-miner

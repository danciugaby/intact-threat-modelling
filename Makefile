.PHONY: install lint test cov e2e sandbox sandbox-offline sandbox-stop demo image

install:          ## install runtime + dev dependencies
	pip install -r requirements-dev.txt

lint:             ## ruff lint
	ruff check .

test:             ## unit + API tests
	pytest -q

cov:              ## tests with coverage (fails under 85%)
	pytest -q --cov --cov-report=term --cov-report=xml

e2e:              ## build the image and run end-to-end tests against it
	docker compose -f docker-compose.e2e.yml up -d --build --wait
	E2E_BASE_URL=http://localhost:5000 pytest -q -m e2e tests/e2e; \
	  rc=$$?; docker compose -f docker-compose.e2e.yml down -v; exit $$rc

sandbox:          ## start API + mock services (live data sources)
	bash sandbox/start.sh

sandbox-offline:  ## start API + mock services without internet
	OFFLINE=1 bash sandbox/start.sh

sandbox-stop:
	bash sandbox/start.sh stop

demo:             ## run the demo against a running sandbox (PILOT=health)
	bash sandbox/demo.sh $(or $(PILOT),health)

image:            ## build the production image
	docker build -t intact-threat-modelling .

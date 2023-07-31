setup:
	./setup.py check && rm dist/* && ./setup.py sdist bdist_wheel 

upload_test:
	twine upload --repository testpypi dist/* 

upload:
	twine upload dist/* 

install_test:
	pip install --index-url https://test.pypi.org/simple/ --no-deps natchecker==0.1.3
set -e

cd $(mktemp -d)

age-keygen -o key.txt

age-plugin-threshold wrap $(cat key.txt | sed -n 3p) > key.wrap.txt

age-plugin-threshold build-recipient -t 1 $(age-keygen -y key.txt) > recipient.txt

echo test | age -R recipient.txt -o test.age

age -d -i key.wrap.txt test.age

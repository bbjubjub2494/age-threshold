generate:
  #!/usr/bin/env bash
  mkdir -p data/2outof3/; cd data/2outof3/
  > recipients
  for i in $(seq 3); do
    rm -f key$i
    age-keygen -o key$i
    age-keygen -y key$i >> recipients
  done
  
  echo -n this is a message for at least two recipients > message
  three -t 2 -R recipients -o message.age message

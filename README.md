# Aladdin
> Diamond in the rough next-gen web connectivity

This is an experiment to explore how specific subsets of the next
generation web connectivity nettest would look like.

The probe-engine/miniooni platform already contains enough functionality
to allow us to implement most of the rest as a bash script for now.

Of course, the final objective is to get this right and rewrite all
this in golang, to be integrated in probe-engine.

This work has been heavily influenced by Jigsaw-Code/net-analysis
blocktest/measure.sh methodology <https://git.io/JfsZb>.

This is alpha code. We will you to explicitly acknowledge you understand
the risks and OONI's privacy policy the first time you run the measurement
script provided by this repository.

## Using a Docker container

Build a suitable docker container:

```bash
docker build -t bassosimone-aladdin .
```

Enter into the container:

```bash
docker run --cap-drop=all -it -v`pwd`:/aladdin -w/aladdin bassosimone-aladdin
```

Run the measurement script from inside the container:

```bash
./domain-check.bash www.google.com
```

Be patient: the first time you run `./domain-check.bash` it will take a
long time to build the `./miniooni` binary from scratch.

## Running the script directly

You need to have Go >= 1.14 installed. Try:

```bash
./domain-check.bash www.google.com
```

The script will tell you whether you're missing other packages.

Be patient: the first time you run `./domain-check.bash` it will take a
long time to build the `./miniooni` binary from scratch.

# Create a backtrace and coredump for an Aurix Tricore

This is a demo that shows how a backtrace can be created for a given memory dump and ELF file for the Aurix Tricore architecture by traversing the return addresses stored in the Context Save Area (CSA) list.

# Roadmap

[ ] Remove the protobuffer dependency by requiring a plain memory dump.
[ ] Use an `--experimental` flag to disable inline+prototype reconstruction and/or call address guessing.
[ ] Include decoding of TIN + class as well as the access location for a given trap dump.
[ ] Prettify the output and/or use an (optional) HTML template.

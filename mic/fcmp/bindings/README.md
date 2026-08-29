# Helios/Selene curve bindings

`helioselene_ct` is the default binding for this project. Basically it runs an OpenSSL
multiplication over Helios and Selene in constant time. To install it manually use:

    pip install pybind11
    bash mic/fcmp/bindings/build.sh   # needs g++ (C++17) and OpenSSL headers
    python -c "from mic.fcmp.bindings import ct; print(ct.backend())"

without it all the Helios/Selene curve multiplications will be done in pure Python
which is really slow.
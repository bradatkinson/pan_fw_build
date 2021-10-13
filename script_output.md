# Initial Run

```
>docker-compose up

Creating network "pan_fw_build_3220_default" with the default driver
Building python
Step 1/9 : FROM python:3.9-slim
 ---> fdbfbc1456f2
Step 2/9 : LABEL maintainer="Brad Atkinson <brad.scripting@gmail.com>"
 ---> Running in 30e398cd6acc
Removing intermediate container 30e398cd6acc
 ---> c40140c0dff0
Step 3/9 : RUN mkdir /code
 ---> Running in e553889bb853
Removing intermediate container e553889bb853
 ---> a2618c39f6e4
Step 4/9 : COPY ./requirements.txt /code
 ---> 6fda614e051f
Step 5/9 : WORKDIR /code
 ---> Running in 9917a49ad6c7
Removing intermediate container 9917a49ad6c7
 ---> f845fb66d962
Step 6/9 : RUN pip install -r requirements.txt
 ---> Running in 248d0a207d8e
Collecting pan-os-python
  Downloading pan_os_python-1.0.2-py2.py3-none-any.whl (122 kB)
Collecting pandevice
  Downloading pandevice-0.14.0.tar.gz (151 kB)
Collecting pan-python<0.17.0,>=0.16.0
  Downloading pan_python-0.16.0-py2.py3-none-any.whl (59 kB)
Building wheels for collected packages: pandevice
  Building wheel for pandevice (setup.py): started
  Building wheel for pandevice (setup.py): finished with status 'done'
  Created wheel for pandevice: filename=pandevice-0.14.0-py2.py3-none-any.whl size=116090 sha256=5f1caa73ce3eb69dd746e605266e8a68e164310ba1f84565eabb7602a0bf0126
  Stored in directory: /root/.cache/pip/wheels/21/7f/b6/45523566899aa5fa9074462925231a6970281bed6f76e5a981
Successfully built pandevice
Installing collected packages: pan-python, pandevice, pan-os-python
Successfully installed pan-os-python-1.0.2 pan-python-0.16.0 pandevice-0.14.0
WARNING: You are using pip version 20.3.1; however, version 20.3.3 is available.
You should consider upgrading via the '/usr/local/bin/python -m pip install --upgrade pip' command.
Removing intermediate container 248d0a207d8e
 ---> 48fe56c565ab
Step 7/9 : COPY ./pan_fw_build.py /code
 ---> 3830dec8764d
Step 8/9 : COPY ./config.py /code
 ---> c3284d3eba58
Step 9/9 : CMD ["python", "-u", "pan_fw_build.py"]
 ---> Running in 6f38f37ecd86
Removing intermediate container 6f38f37ecd86
 ---> e0eca6359968

Successfully built e0eca6359968
Successfully tagged pan_fw_build_python:latest
WARNING: Image for service python was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
Creating pan_fw_build ... done
Attaching to pan_fw_build
pan_fw_build | Connecting to FW-Test-01...
pan_fw_build | -- Connected
pan_fw_build | Applying management configs...
pan_fw_build | -- Applied
pan_fw_build | Removing factory default configs...
pan_fw_build | -- Removed
pan_fw_build | Committing configs...
pan_fw_build | -- Committed
pan_fw_build | Licenses retrieved from Palo Alto Networks
pan_fw_build | Downloading latest content update...
pan_fw_build | -- Downloaded
pan_fw_build | Installing latest content update...
pan_fw_build | -- Installed
pan_fw_build | HA already enabled
pan_fw_build | Remediating weak SSH ciphers...
pan_fw_build | -- Successfully restarted SSH service...  success
pan_fw_build | -- Remediated
pan_fw_build | Upgrading PAN-OS version...
pan_fw_build | -- Upgraded
pan_fw_build | Connecting to FW-Test-02...
pan_fw_build | -- Connected
pan_fw_build | Applying management configs...
pan_fw_build | -- Applied
pan_fw_build | Removing factory default configs...
pan_fw_build | -- Removed
pan_fw_build | Committing configs...
pan_fw_build | -- Committed
pan_fw_build | Licenses retrieved from Palo Alto Networks
pan_fw_build | Downloading latest content update...
pan_fw_build | -- Downloaded
pan_fw_build | Installing latest content update...
pan_fw_build | -- Installed
pan_fw_build | HA already enabled
pan_fw_build | Remediating weak SSH ciphers...
pan_fw_build | -- Successfully restarted SSH service...  success
pan_fw_build | -- Remediated
pan_fw_build | Upgrading PAN-OS version...
pan_fw_build | -- Upgraded
pan_fw_build exited with code 0
```

# Rerun

```
Creating pan_fw_build ... done
Attaching to pan_fw_build
pan_fw_build | Connecting to FW-Test-01...
pan_fw_build | -- Connected
pan_fw_build | Applying management configs...
pan_fw_build | -- Already applied
pan_fw_build | Removing factory default configs...
pan_fw_build | -- Already removed
pan_fw_build | No commit needed!
pan_fw_build | Licenses retrieved from Palo Alto Networks
pan_fw_build | Newest content updates already installed
pan_fw_build | HA already enabled
pan_fw_build | Ciphers handled by Panorama
pan_fw_build | Firewall already at PAN-OS version 10.0.7
pan_fw_build | Connecting to FW-Test-02...
pan_fw_build | -- Connected
pan_fw_build | Applying management configs...
pan_fw_build | -- Already applied
pan_fw_build | Removing factory default configs...
pan_fw_build | -- Already removed
pan_fw_build | No commit needed!
pan_fw_build | Licenses retrieved from Palo Alto Networks
pan_fw_build | Newest content updates already installed
pan_fw_build | HA already enabled
pan_fw_build | Ciphers handled by Panorama
pan_fw_build | Firewall already at PAN-OS version 10.0.7
pan_fw_build exited with code 0
```
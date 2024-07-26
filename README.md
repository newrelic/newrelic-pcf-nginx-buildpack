<a href="https://opensource.newrelic.com/oss-category/#community-project"><picture><source media="(prefers-color-scheme: dark)" srcset="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/dark/Community_Project.png"><source media="(prefers-color-scheme: light)" srcset="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/Community_Project.png"><img alt="New Relic Open Source community project banner." src="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/Community_Project.png"></picture></a>

![GitHub forks](https://img.shields.io/github/forks/newrelic/newrelic-pcf-nginx-buildpack?style=social)
![GitHub stars](https://img.shields.io/github/stars/newrelic/newrelic-pcf-nginx-buildpack?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/newrelic/newrelic-pcf-nginx-buildpack?style=social)

![GitHub all releases](https://img.shields.io/github/downloads/newrelic/newrelic-pcf-nginx-buildpack/total)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/newrelic/newrelic-pcf-nginx-buildpack)
![GitHub last commit](https://img.shields.io/github/last-commit/newrelic/newrelic-pcf-nginx-buildpack)
![GitHub Release Date](https://img.shields.io/github/release-date/newrelic/newrelic-pcf-nginx-buildpack)


![GitHub issues](https://img.shields.io/github/issues/newrelic/newrelic-pcf-nginx-buildpack)
![GitHub issues closed](https://img.shields.io/github/issues-closed/newrelic/newrelic-pcf-nginx-buildpack)
![GitHub pull requests](https://img.shields.io/github/issues-pr/newrelic/newrelic-pcf-nginx-buildpack)
![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/newrelic/newrelic-pcf-nginx-buildpack)


---

# New Relic Nginx Integration Buildpack for VMware Tanzu

The New Relic Nginx Integration Buildpack for VMware Tanzu enables seamless monitoring and troubleshooting of your NGINX server. This buildpack collects and sends comprehensive data, including inventory and metrics, to the New Relic platform. This integration provides valuable insights into connections and client requests, allowing for quick issue identification and resolution. Additionally, you can correlate this data with VMware Tanzu infrastructure metrics and events collected by the [New Relic Firehose Nozzle](https://support.broadcom.com/group/ecx/productdownloads?subfamily=New%20Relic%20Nozzle%20for%20VMware%20Tanzu), gaining a complete understanding of your environment and streamlining your troubleshooting process.

## Installation and Configuration

This section describes how to install and configure the New Relic Nginx Integration Buildpack for VMware Tanzu.

You can install the buildpacks either as a tile in Ops Manager or individually using the CF CLI.

### <a id='install-opsmgr'></a> Install and Configure New Relic Nginx Integration Buildpack as a Tile in Ops Manager

1. Download the latest version of the tile (currently **"newrelic-nginx-buildpack-1.0.1.pivotal"**) from the [Broadcom download site](https://support.broadcom.com/group/ecx/productdownloads?subfamily=New%20Relic%20Nginx%20Integration%20Buildpack%20for%20VMware%20Tanzu), or from New Relic's [GitHub repo under releases](https://github.com/newrelic/newrelic-pcf-nginx-buildpack/releases).
2. Navigate to the Ops Manager Installation Dashboard and click **Import a Product** to upload the product file.
3. Under the **Import a Product** button, click the **"+"** sign next to the version number of **New Relic Nginx Buildpack for Tanzu** to add the tile to your staging area.
4. Click the newly added **New Relic Nginx Buildpack for Tanzu** tile.
5. Install and configure the tile in Ops Manager. You can accept the default values to install both buildpacks in your PCF foundation or select the checkbox for any buildpacks you wish to install under **Tile Configuration → New Relic Buildpack Selection**.
6. If you make any configuration changes, click the **"Save"** button on each tab at the bottom of the page.
7. Go to the **Installation UI** of Ops Manager.
8. Click the blue button in the top-right corner of the Installation UI to **Apply changes**.

### <a id='install-buildpack'></a> Install and Configure Nginx Buildpack for Tanzu with CF CLI

If you prefer not to install the tile, you can alternatively unzip the downloaded **.pivotal** file and install the buildpacks using the CF CLI command **"cf create-buildpack ..."**.

1. Unzip **"newrelic-nginx-buildpack-*.pivotal"** into a separate subdirectory:
    ```sh
    unzip newrelic-nginx-buildpack-*.pivotal -d buildpack_tile
    ```
2. Change directory to `buildpack_tile/releases`:
    ```sh
    cd buildpack_tile/releases
    ```
3. Create a subdirectory (e.g., `tmp`):
    ```sh
    mkdir tmp
    ```
4. Extract the **.tgz** file in the releases folder into the **tmp** directory:
    ```sh
    tar xvf newrelic-nginx-buildpack-*.tgz -C tmp
    ```
5. Change directory to **tmp/packages**:
    ```sh
    cd tmp/packages
    ```
6. Extract any of the individual buildpack **.tgz** files using the following command:
    ```sh
    tar xvf newrelic_nginx_buildpack_cflinuxfs4.tgz
    ```
    OR
    ```sh
    tar xvf newrelic_nginx_buildpack_cflinuxfs3.tgz
    ```
    This will create a folder with the name of the buildpack, containing the zipped version of the buildpack.

7. Upload the zipped buildpack file using the CF CLI's **"cf create-buildpack"** command:
    ```sh
    cf create-buildpack newrelic_nginx_buildpack newrelic_nginx_buildpack-cached-cflinuxfs4-v1.0.6.zip 99
    ```
    OR
    ```sh
    cf create-buildpack newrelic_nginx_buildpack newrelic_nginx_buildpack-cached-cflinuxfs3-v1.0.6.zip 99
    ```

## <a id='buildpack-build-deploy'></a> Buildpack Build and Deploy Process

### <a id='build'></a> Build

The buildpacks in this tile are pre-built and ready for use in Cloud Foundry. However, if you want to make changes or update the cached version of any buildpacks with newer dependencies, you can build your own copy. Follow the instructions below to build your own copy:

1. Clone the buildpack repository to your system:
    ```sh
    git clone https://github.com/newrelic/newrelic-pcf-nginx-buildpack
    ```
2. Change directory to the cloned buildpack.
3. Source the **.envrc** file in the buildpack directory:
    ```sh
    source .envrc
    ```
4. Install **Bosh CLI** and **Tile Generator**:
    ```sh
    ./scripts/setup.sh
    ```
5. Build the buildpack:
    ```sh
    make clean
    make package
    ```
    OR
    Build the buildpack and create a tile:
    ```sh
    make clean
    make all
    ```

### <a id='deploy'></a> Deploy

To deploy and use the buildpack in Cloud Foundry:

1. Upload the buildpack to Cloud Foundry and optionally specify it by name using the CF CLI:
    ```sh
    cf create-buildpack newrelic_nginx_buildpack [BUILDPACK_ZIP_FILE_PATH] 99
    ```
2. Create a folder named `example` and download the `examples.zip` archive:
    ```sh
    mkdir example
    cd example
    wget https://github.com/newrelic/newrelic-pcf-nginx-buildpack/releases/examples.zip
    ```

### Example Directory

The `example` directory contains various artifacts necessary for the buildpack. Below is a description of each artifact and related documentation for reference:

```
example/
├── buildpack.yml
├── manifest.yml
├── mime.types
├── nginx-config.yml
├── nginx.conf
└── public
    └── index.html
```

#### Artifacts Description:

- **[buildpack.yml](https://docs.cloudfoundry.org/buildpacks/nginx/index.html):**
  - Contains configuration for the buildpack.
  - **Action Required:** Update the Nginx version information to ensure compatibility with the latest version of the Nginx buildpack.

- **manifest.yml:**
  - Defines the application-related configurations and metadata.
  - **Action Required:** Update this file with the correct application information and ensure the buildpack order is correctly specified. This is crucial for the proper deployment of your application.
  - **New Relic License Key:** This integration requires a New Relic License key. You can set it in the `manifest.yml` file using the environment variable `NEW_RELIC_LICENSE_KEY: <ingest_key_value>`. Alternatively, the license key can be obtained from the New Relic service broker by binding the application.
  - **Status Port:** Based on your Nginx configuration, the status port information is required. The default port value is `8080`, which can be set using the environment variable `STATUS_PORT: 8080`.
  - **Note:** Additional [environmental variables](https://docs.newrelic.com/docs/infrastructure/install-infrastructure-agent/configuration/infrastructure-agent-configuration-settings/) can be set as per your requirements.
  - The `nginx_buildpack` must be installed before `newrelic_nginx_buildpack` as the latter requires the former to function correctly.
    e.g ``` cf push my_app -b nginx_buildpack -b newrelic_nginx_buildpack ```
    [Refer - use multiple buildpacks](https://docs.cloudfoundry.org/buildpacks/use-multiple-buildpacks.html)
  - [nginx_buildpack documentation](https://docs.cloudfoundry.org/buildpacks/nginx/index.html)

- **[mime.types](https://docs.cloudfoundry.org/buildpacks/nginx/index.html):**
  - Specifies MIME types required by the Nginx buildpack.
  - **Note:** Required by the Nginx buildpack for serving different file types with appropriate MIME types.

- **[nginx.conf](https://docs.cloudfoundry.org/buildpacks/nginx/index.html):**
  - A primary Template configuration file for Nginx.
  - **Note:** Required by the Nginx buildpack to configure how Nginx serves the application. Ensure that `location /nginx_status` in `nginx.conf` matches the `STATUS_URL` in `nginx-config.yml`.

- **[nginx-config.yml](https://docs.newrelic.com/install/nginx/):**
  - A Template Contains configuration settings for New Relic Nginx Integration.
  - **Action Required:** Refer to the [New Relic Nginx documentation](https://docs.newrelic.com/install/nginx/) to understand various configuration options and adjust settings as necessary.
  - **Note:** Ensure that the `location /nginx_status` in `nginx.conf` matches the `STATUS_URL` in `nginx-config.yml`.

- **public:**
  - Contains static files that Nginx will serve.
  - **Note:** The `index.html` file is crucial as the default file served by Nginx.

### Additional Notes:

- Ensure all configuration files are updated according to the latest documentation and version requirements.
- Proper configuration is essential for the correct functionality of the buildpack and the application it serves.

Finally, push the application using the `cf push` command by using the manifest.yml :
    ```sh
    cf push
    ```

### Optional: Binding Your Application to New Relic Broker Service

To integrate your application with the [New Relic Broker Service](https://docs.newrelic.com/docs/infrastructure/host-integrations/host-integrations-list/cloudfoundry-integrations/vmware-tanzu-service-broker-integration/), follow these steps:

1. **Create a New Relic Service Instance:**
    Use the Cloud Foundry CLI to create a New Relic service instance:
    ```sh
    cf create-service newrelic <NEWRELIC_PLAN_NAME> <YOUR_NEWRELIC_SERVICE_INSTANCE_NAME>
    ```
    Replace `<NEWRELIC_PLAN_NAME>` with the desired New Relic plan and `<YOUR_NEWRELIC_SERVICE_INSTANCE_NAME>` with a name for your service instance.

2. **Bind the New Relic Service to Your Application:**
    Bind your application to the New Relic service instance using the CF CLI:
    ```sh
    cf bind-service my_app <YOUR_NEWRELIC_SERVICE_INSTANCE_NAME>
    ```
    Replace `my_app` with the name of your application and `<YOUR_NEWRELIC_SERVICE_INSTANCE_NAME>` with the name of the New Relic service instance you created.

3. **Update the Application Manifest:**
    Specify the New Relic service instance in the `services` section of your application's `manifest.yml` file:
    ```yaml
    services:
      - <YOUR_NEWRELIC_SERVICE_INSTANCE_NAME>
    ```

4. **Push the Application:**
    Deploy your application with the updated manifest:
    ```sh
    cf push
    ```

### Monitoring with New Relic

Once the application is successfully pushed, the New Relic Nginx integration will start sending NGINX metrics to New Relic.

To install the dashboard, click [here](https://one.newrelic.com/catalog-pack-details?state=952adb8f-8cd8-17ec-a55e-2a470ff27b54). You should skip the installation and directly install the dashboard.

<img width="962" alt="image" src="https://github.com/user-attachments/assets/bb88156c-4e9f-4ad1-80dd-da2778ed57fa">

You may also explore data further under "All entities" → "On Hosts" → "NGINX Servers."

---
## Support

New Relic has open-sourced this project.  Issues and contributions should be reported to the project here on GitHub.

>We encourage you to bring your experiences and questions to the [Explorers Hub](https://forum.newrelic.com) where our community members collaborate on solutions and new ideas.

## Contributing

We encourage your contributions to improve Salesforce Commerce Cloud for New Relic Browser! Keep in mind when you submit your pull request, you'll need to sign the CLA via the click-through using CLA-Assistant. You only have to sign the CLA one time per project. If you have any questions, or to execute our corporate CLA, required if your contribution is on behalf of a company, please drop us an email at opensource@newrelic.com.

**A note about vulnerabilities**

As noted in our [security policy](../../security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

## License

New Relic Java Instrumentation for RMI is licensed under the [Apache 2.0](http://apache.org/licenses/LICENSE-2.0.txt) License.

>[If applicable: [Project Name] also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the third-party notices document.]


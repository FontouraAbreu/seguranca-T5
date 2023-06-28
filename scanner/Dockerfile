FROM mikesplain/openvas:latest

RUN apt update && apt install -y \
    tcpreplay

ENV FEED=feed.community.greenbone.net
ENV COMMUNITY_NVT_RSYNC_FEED=rsync://$FEED:/nvt-feed
ENV COMMUNITY_CERT_RSYNC_FEED=rsync://$FEED:/cert-data
ENV COMMUNITY_SCAP_RSYNC_FEED=rsync://$FEED:/scap-data
#RUN greenbone-nvt-sync
#RUN greenbone-certdata-sync
#RUN greenbone-scapdata-sync
#RUN service openvas-scanner restart
#RUN service openvas-manager restart
#RUN service openvas-gsa restart
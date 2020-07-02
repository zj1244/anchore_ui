$("#add_submit").click(function () {

    form = $("form#add_sync_form");
    messenger = Messenger();
    $.ajax({
        type: "POST",
        url: "/images_sync?action=add",
        data: form.serialize(),
        success: function (data) {
            var response = JSON.parse(data);
            if (response.status == "success") {
                messenger.post({
                    message: response.content,
                    type: "success"
                });
                setTimeout(" window.location.href = '" + response.redirect + "'", 3000);


            } else if (response.status == "error")
                messenger.post({
                    message: response.content,
                    type: "error"
                })
        }
    });
    return false;
});



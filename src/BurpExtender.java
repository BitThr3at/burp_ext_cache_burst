import burp.*;

import javax.swing.*;
import java.awt.*;
import java.security.SecureRandom;
import java.util.List;

public class BurpExtender implements IBurpExtender, IProxyListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel panel;
    private JCheckBox enableCheckbox;
    private JSpinner nameLenSpinner;
    private JSpinner valueLenSpinner;

    private final SecureRandom random = new SecureRandom();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Cache Buster (Query Param)");

        // Build minimal UI
        panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.anchor = GridBagConstraints.WEST;

        enableCheckbox = new JCheckBox("Enable cache-busting query param (random name + value)", true);
        nameLenSpinner = new JSpinner(new SpinnerNumberModel(6, 1, 64, 1));
        valueLenSpinner = new JSpinner(new SpinnerNumberModel(8, 1, 128, 1));

        int row = 0;

        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        panel.add(enableCheckbox, c);
        row++;

        c.gridwidth = 1;
        c.gridx = 0; c.gridy = row;
        panel.add(new JLabel("Random name length:"), c);
        c.gridx = 1;
        panel.add(nameLenSpinner, c);
        row++;

        c.gridx = 0; c.gridy = row;
        panel.add(new JLabel("Random value length:"), c);
        c.gridx = 1;
        panel.add(valueLenSpinner, c);
        row++;

        JLabel note = new JLabel("<html><i>Adds a URL query parameter like bcb_<b>RANDOM</b>=<b>RANDOM</b> to each proxied request.</i></html>");
        c.gridx = 0; c.gridy = row; c.gridwidth = 2;
        panel.add(note, c);

        callbacks.addSuiteTab(this);
        callbacks.registerProxyListener(this);
    }

    @Override
    public String getTabCaption() {
        return "Cache Buster";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage intercepted) {
        if (!messageIsRequest) return;
        if (!enableCheckbox.isSelected()) return;

        IHttpRequestResponse messageInfo = intercepted.getMessageInfo();
        byte[] request = messageInfo.getRequest();
        if (request == null) return;

        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        if (reqInfo == null) return;

        // Skip CONNECT tunnel setup
        String method = reqInfo.getMethod();
        if (method != null && method.equalsIgnoreCase("CONNECT")) return;

        // Avoid adding multiple times: if a URL param already starts with our prefix, skip
        List<IParameter> params = reqInfo.getParameters();
        for (IParameter p : params) {
            if (p.getType() == IParameter.PARAM_URL && p.getName() != null && p.getName().startsWith("bcb_")) {
                return;
            }
        }

        int nameLen = (Integer) nameLenSpinner.getValue();
        int valueLen = (Integer) valueLenSpinner.getValue();

        String paramName = "bcb_" + randomString(nameLen);
        String paramValue = randomString(valueLen);

        IParameter cacheBust = helpers.buildParameter(paramName, paramValue, IParameter.PARAM_URL);
        byte[] updated = helpers.addParameter(request, cacheBust);
        messageInfo.setRequest(updated);
    }

    private static final char[] ALPHANUM =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

    private String randomString(int len) {
        char[] buf = new char[len];
        for (int i = 0; i < len; i++) {
            buf[i] = ALPHANUM[random.nextInt(ALPHANUM.length)];
        }
        return new String(buf);
    }
}

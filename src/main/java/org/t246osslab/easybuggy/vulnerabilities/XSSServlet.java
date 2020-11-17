package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;
import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/xss" })
public class XSSServlet extends AbstractServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        try {
            String string = req.getParameter("string");
            Locale locale = req.getLocale();

            StringBuilder bodyHtml = new StringBuilder();

            bodyHtml.append("<form action=\"xss\" method=\"post\">");
            bodyHtml.append(getMsg("description.reverse.string", locale));
            bodyHtml.append("<br><br>");
            bodyHtml.append(getMsg("label.string", locale) + ": ");
            bodyHtml.append("<input type=\"text\" name=\"string\" size=\"100\" maxlength=\"100\">");
            bodyHtml.append("<br><br>");
            bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.submit", locale) + "\">");
            bodyHtml.append("<br><br>");

            if (!StringUtils.isBlank(string)) {
                // Reverse the given string
                String reversedName = StringUtils.reverse(string);
                //trung-nguyen 2020-11-17 validate xss
                reversedName = validateXSS(reversedName);
                
                bodyHtml.append(getMsg("label.reversed.string", locale) + " : "
                        + reversedName);
            } else {
                bodyHtml.append(getMsg("msg.enter.string", locale));
            }
            bodyHtml.append("<br><br>");
            bodyHtml.append(getInfoMsg("msg.note.xss", locale));
            bodyHtml.append("</form>");

            responseToClient(req, res, getMsg("title.xss.page", locale), bodyHtml.toString());

        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        }
    }
    
    //method filter and replace xss
    private String validateXSS(String value) {
		String result = null;
		if (value != null) {
			result = Normalizer.normalize(value, Normalizer.Form.NFD);

			// Avoid null characters
			result = result.replaceAll("\0", "");
			
			// Avoid anything between script tags
			Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
			result = scriptPattern.matcher(result).replaceAll("");
	 
			// Avoid anything in a src='...' type of expression
			scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");

			scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");
			
			// Remove any lonesome </script> tag
			scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
			result = scriptPattern.matcher(result).replaceAll("");

			// Remove any lonesome <script ...> tag
			scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");

			// Avoid eval(...) expressions
			scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");
			
			// Avoid expression(...) expressions
			scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");
			
			// Avoid javascript:... expressions
			scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
			result = scriptPattern.matcher(result).replaceAll("");
			
			// Avoid vbscript:... expressions
			scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
			result = scriptPattern.matcher(result).replaceAll("");
			
			// Avoid onload= expressions
			scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
			result = scriptPattern.matcher(result).replaceAll("");
		}
		System.out.println(result);
		return result;
	}
}
